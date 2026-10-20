# Wazuh OVA 설치 · 에이전트 배포 런북

> 출처: 본인 작성 노트(Notion) 정리 · 정리일 2026-10-20
> 용도: 프로젝트 탐지 계층(SIEM/HIDS) 구축 기록. 제안서 04(통합)·05(탐지)의 "Wazuh" 트랙 실체.
> 성격: **런북**(따라 하면 재현됨). 이론 설명이 아니라 실행 순서·검증 중심.
> 표기: `<...>`는 환경마다 바꿔 넣는 값(placeholder). 실제 IP는 커밋하지 말 것.

---

## 0. 환경

- VMware Workstation
- `wazuh-4.14.9.ova` (올인원: manager + indexer + dashboard)
- 에이전트 대상: Rocky Linux 9.4, Windows 11
- 관리 단말: Win11 (PowerShell)

## 0-1. 사전 확인 (포트·접속) — ※ 원 노트 보강

| 포트 | 용도 | 방향 |
|---|---|---|
| 1514/tcp | 에이전트 ↔ 매니저 로그 통신 | 에이전트 → 서버 |
| 1515/tcp | 에이전트 등록(enrollment) | 에이전트 → 서버 |
| 55000/tcp | Wazuh API | 관리 도구 → 서버 |
| 443/tcp | 대시보드(웹 UI) | 브라우저 → 서버 |

- 대시보드 접속: `https://<wazuh-server-ip>` (자체서명 인증서 경고는 통과)
- 에이전트와 서버가 **서로 통신 가능한 네트워크**인지 먼저 확인(ping/방화벽).

---

## 1. Wazuh 서버 구축 (OVA)

1. VMware에 **OVA import** → VM 시작
2. 로그인(콘솔)
   ```
   user: wazuh-user
   password: wazuh
   ```
3. 대시보드 로그인: 브라우저에서 `https://<wazuh-server-ip>` 접속
   - (대시보드 계정은 OVA 기본값 사용. 최초 접속 후 비밀번호 변경 권장)

### 트러블슈팅 — 기동 중 서비스 중단 (실제 겪음)
- 증상: Wazuh 구성요소(indexer/manager/dashboard) **기동에 시간이 오래 걸려** 서비스가 자동 중단됨.
- 해결: service 등록(systemd) 시 **대기(Timeout) 시간을 늘려** 기동 완료 전에 죽지 않게 함.

---

## 2. 리눅스(Rocky 9.4) 에이전트 배포 (CLI)

1. **GPG 키 import**
   ```
   rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
   ```
2. **저장소 추가** (EL9)
   ```
   cat > /etc/yum.repos.d/wazuh.repo << EOF
   [wazuh]
   gpgcheck=1
   gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
   enabled=1
   name=EL-\$releasever - Wazuh
   baseurl=https://packages.wazuh.com/4.x/yum/
   priority=1
   EOF
   ```
3. **설치** (매니저 IP 지정 → 설치 시 자동 등록)
   ```
   WAZUH_MANAGER="<wazuh-server-ip>" yum install wazuh-agent
   ```
4. **서비스 등록·시작**
   ```
   systemctl daemon-reload
   systemctl enable wazuh-agent
   systemctl start wazuh-agent
   ```

### 트러블슈팅 — 잘못된 매니저 주소 (실제 겪음)
- 증상: 에이전트가 매니저에 안 붙음. `ossec.conf`에 **옛/잘못된 주소**가 남아 있었음.
- 해결: 설정 파일에서 `<address>`를 올바른 서버 IP로 수정 후 재시작.
   ```
   vim /var/ossec/etc/ossec.conf
   ```
   ```
   <server>
     <address><wazuh-server-ip></address>
     <port>1514</port>
     <protocol>tcp</protocol>
   </server>
   ```
   ```
   systemctl restart wazuh-agent
   ```

---

## 3. 윈도우(Win11) 에이전트 배포

1. MSI 인스톨러 다운로드 (`wazuh-agent-4.14.9-1.msi`)
2. **설치** (PowerShell, 관리자 권한) — 매니저 IP 지정
   ```powershell
   msiexec.exe /i .\wazuh-agent-4.14.9-1.msi /q WAZUH_MANAGER="<wazuh-server-ip>"
   ```
3. **서비스 시작**
   ```powershell
   Start-Service wazuhsvc
   ```
4. 설정 파일 위치 (필요 시 주소 수정)
   ```
   notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
   ```

---

## 4. 설치 검증 ✅ — ※ 원 노트에 없던 핵심 추가

런북은 "깔았다"가 아니라 **"붙었다"를 확인**해야 끝난다.

- **대시보드**: `Agents` 메뉴에서 리눅스/윈도우 에이전트가 **`Active`(초록)** 로 보이면 성공.
- **서버에서 확인**(매니저 콘솔):
  ```
  /var/ossec/bin/agent_control -l
  ```
  → 등록된 에이전트 목록과 상태(Active) 출력.
- **에이전트에서 확인**:
  - Linux: `systemctl status wazuh-agent` (active running)
  - Windows: `Get-Service wazuhsvc` (Running)
- **로그가 올라오는지**: 대시보드 `Security events`에 해당 에이전트 이벤트가 들어오면 완결.

### 안 붙을 때 점검 순서
1. 서버 IP·포트(1514/1515) 통신 되나 (방화벽/`firewall-cmd`, 보안그룹)
2. `ossec.conf`의 `<address>`가 맞나 (2번 트러블슈팅)
3. 에이전트 시간(NTP) 어긋나지 않았나
4. 등록 실패 시 수동 등록(`agent-auth` / 대시보드의 "Deploy new agent" 명령 재발급)

---

## 5. 프로젝트 연결 (왜 이걸 세웠나)

- 이 Wazuh가 제안서 **04·05의 "탐지 계층"** 실체다.
- 다음 단계(선택): 07 신한 API 실습의 **조회 로그(JSONL)를 Wazuh로 수집**해, 코드 내장 scorer 대신 **Wazuh 룰/대시보드로 이상행위(과다 조회·IDOR 징후)를 탐지**하도록 확장 가능.
- 즉 "직접 만든 탐지(07) → 실무 SIEM(Wazuh)"로 올리는 다리.

## 5-1. 구성 이해 — 올인원 vs ELK (자주 헷갈림)

- **Wazuh = 보안용으로 미리 세팅된 ELK 세트.** OVA는 아래 3개를 VM 한 대에 몰아넣은 "올인원".

| ELK 스택 | Wazuh 구성요소 | 역할 |
|---|---|---|
| Logstash/Beats | Wazuh agent + manager | 로그 수집·가공·룰 적용 |
| Elasticsearch | Wazuh **indexer** (OpenSearch 계열) | 저장·검색 엔진 |
| Kibana | Wazuh **dashboard** (Kibana 계열) | 웹 UI |

- **Kibana 따로 연결 불필요**: 접속하는 대시보드(`https://<server-ip>`)가 Kibana 역할을 하는 Wazuh dashboard다. OVA에 포함·연결 완료 상태.
- **"한 서버에 다 올림" vs "따로"**: 같은 소프트웨어의 **배치 차이**일 뿐. 나누는 이유는 오직 **규모**(대용량 로그 시 indexer 분산). **학생 랩은 올인원이 정답**(나누면 관리만 복잡).
- **ELK와의 차이**: ELK는 빈 로그 플랫폼(룰·에이전트 직접 구축). Wazuh는 에이전트·수천 개 탐지 룰·FIM·규정점검이 기본 내장된 보안 완제품.

## 6. 참고

- Wazuh 공식 문서: docs.wazuh.com (Installation guide / Deploying agents)
- 버전: Wazuh 4.14.9
