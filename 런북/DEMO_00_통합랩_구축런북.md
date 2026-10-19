# DEMO 통합 랩 구축 런북
# 망분리 완화 시대 금융권 탐지·대응 체계 (메일→접근통제→IPS→EDR→XDR/AI)

> 작성일: 2026-10-19 · 상태: 구축 가이드(실습용) · 대상: 팀 프로젝트(새싹)
> 범위: 제안서 00/02/03/04/05를 **한 랩에서 실제로 구축·검증**하기 위한 단계별 런북
> ⚠️ 전제: 모든 작업은 **인터넷과 격리된 폐쇄 랩(VM)**에서만. 실제 악성코드·외부 발송·실자산 스캔 금지.

---

## 0. 문서 지도

| 파일 | 역할 |
|---|---|
| **DEMO_00_통합랩_구축런북.md** (이 문서) | 전체 구축 절차 |
| DEMO_01_설정파일모음.md | 복붙용 config/룰 전문 |
| DEMO_02_발표데모_대본.md | 시연 타임라인·멘트 |
| 00~06_*.md | 각 트랙 제안서(배경·근거) |

진행 순서: **1장(토폴로지) → 2장(공통인프라) → 3~6장(트랙별) → 7장(XDR)+7.5(SOAR/Slack) → 8장(AI)+8.5(Prometheus/Grafana) → 9장(평가) → 10장(데모)**

### 전체 파이프라인 한눈에
```
 [공격]                          [탐지]                [연계]        [대응·통보]        [가시화]
 피싱(00)/옆문(05)/        Rspamd·Suricata·        XDR 상관      SOAR(Shuffle)      Grafana
 WebLogic(03)/건라(02)  →  Sysmon·Wazuh        →   (7장)     →   +AI Slack 훅   →   +Prometheus
                           +AI 분류(8장)                          (7.5)              (8.5)
                                                                    │
                                                            자동 격리·차단·케이스(TheHive)
```

---

## 1. 랩 토폴로지 & 리소스 계획

### 1.1 네트워크 설계 (망분리 완화 환경 모사)

```
                        [ 공격자 VM (Kali) ]  10.10.99.10
                                 │
        ┌────────────────────────┼─────────────────────────┐
        │                  (ext) 10.10.0.0/24  "인터넷/외부"           │
        │                        │                                    │
   ┌──────────┐          ┌──────────────┐                     ┌──────────────┐
   │ 메일서버  │10.10.0.20 │ 옆문 웹서버   │10.10.0.30            │ WebLogic 서버 │10.10.0.40
   │ Postfix  │          │ (부속시스템)   │                     │ (vulhub)      │
   └──────────┘          └──────────────┘                     └──────────────┘
        │  ────────────── 완화된 경계(방화벽/pfSense) ──────────────  │
        │                  (int) 10.10.20.0/24  "내부 업무망"          │
   ┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │ 엔지니어PC │   │ 업무 PC(Win) │   │ AD/DC(선택)   │   │ 관리/SIEM     │
   │ 10.20.0.50│   │ 10.20.0.51   │   │ 10.20.0.5     │   │ 10.20.0.9     │
   │ Sysmon    │   │ Sysmon       │   │               │   │ Wazuh/ELK     │
   └──────────┘   └──────────────┘   └──────────────┘   └──────────────┘
                         │ span/mirror → IPS(Suricata) 10.20.0.8 │
```

- **ext(10.10.0.0/24)**: 외부 노출 자산(메일·옆문·WebLogic). 공격자가 보는 영역.
- **int(10.20.0.0/24)**: 내부 업무망. 망분리 완화로 ext와 제한적으로 연결됨.
- **경계**: pfSense(또는 Linux iptables) 1대로 두 망 사이 라우팅/필터.
- **IPS**: 경계 또는 미러포트에서 트래픽 관찰(Suricata).
- **SIEM**: 전 구간 로그 집중(Wazuh + Elastic).

### 1.2 VM 목록 & 스펙

| # | VM | OS | vCPU | RAM | 용도 | 트랙 |
|---|---|---|---|---|---|---|
| 1 | gw-fw | pfSense/Debian | 1 | 1GB | 경계 방화벽/라우터 | 공통 |
| 2 | siem | Ubuntu 22.04 | 2 | 6GB | Wazuh+Elastic+Kibana | 공통/XDR |
| 3 | mail | Ubuntu 22.04 | 2 | 2GB | Postfix/Dovecot/Rspamd | 00 |
| 4 | sidedoor | Ubuntu 22.04 | 1 | 1GB | 취약 웹 부속시스템+Keycloak | 05 |
| 5 | weblogic | Docker host(Ubuntu) | 2 | 3GB | vulhub WebLogic CVE | 03 |
| 6 | ips | Ubuntu 22.04 | 2 | 2GB | Suricata(IDS/IPS) | 03 |
| 7 | win-eng | Windows 10/11 | 2 | 4GB | 엔지니어 PC+Sysmon | 02/00 |
| 8 | win-biz | Windows 10/11 | 2 | 4GB | 업무 PC+Sysmon | 02 |
| 9 | attacker | Kali | 2 | 2GB | 공격자(트래픽 생성) | 전체 |
| 10 | soar | Ubuntu 22.04 | 2 | 4GB | Shuffle(SOAR)+TheHive+Cortex | 7.5 |
| 11 | obsv | Ubuntu 22.04 | 2 | 3GB | Prometheus+Grafana+Alertmanager | 8.5 |
| (12) | dc | Windows Server | 2 | 4GB | AD 도메인(선택) | 02/05 |

> 리소스 절약: soar·obsv는 siem VM에 **컨테이너로 합칠 수 있음**(docker compose). 최소구성에선 siem 1대에 Wazuh+Shuffle+Prometheus+Grafana를 올림(RAM 10GB 권장).

- **최소 구성**(리소스 부족 시): 1·2·3·5·6·7·9 = 7대. 옆문(4)은 weblogic(5)과 합치고, win-biz·dc 생략 가능.
- **호스트 요구**: 총 RAM ≥ 24GB 권장(최소 16GB로 축소 구성 가능). 디스크 ≥ 200GB SSD.
- **가상화**: VirtualBox/VMware/Proxmox 중 택1. 스냅샷 필수(공격 전/후 롤백).

### 1.3 IP·호스트명 표 (고정 IP 권장)

| 호스트 | IP | 비고 |
|---|---|---|
| gw-fw | 10.10.0.1 / 10.20.0.1 | 양 망 게이트웨이 |
| siem | 10.20.0.9 | Kibana :5601, Wazuh :1514/1515 |
| mail | 10.10.0.20 | SMTP :25/587, IMAP :993 |
| sidedoor | 10.10.0.30 | web :8080, keycloak :8443 |
| weblogic | 10.10.0.40 | :7001 |
| ips | 10.20.0.8 | 미러 수신 |
| soar | 10.20.0.7 | Shuffle :3443, TheHive :9000 |
| obsv | 10.20.0.6 | Grafana :3000, Prometheus :9090 |
| win-eng | 10.20.0.50 | |
| win-biz | 10.20.0.51 | |
| attacker | 10.10.99.10 | ext에서 접근 |

---

## 2. 공통 인프라 구축

### 2.1 네트워크 격리 (가장 먼저)

1. 가상 네트워크 2개 생성: `ext`(10.10.0.0/24), `int`(10.20.0.0/24) — **둘 다 Host-Only/Internal**. NAT·Bridged 금지(인터넷 차단).
2. gw-fw에 양쪽 NIC 연결, IP 포워딩 활성:
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   ```
3. 초기엔 전면 허용으로 연결 확인 후, 7장에서 정책을 조인다.
4. 각 VM에서 `ping 8.8.8.8` 실패(인터넷 차단) + 내부 통신 성공 확인.

> 패키지 설치가 필요하면: 구축 단계에서만 임시로 NAT를 켜 설치 → **설치 완료 후 즉시 NAT 제거**하고 스냅샷. 공격 실습 중엔 반드시 인터넷 차단.

### 2.2 중앙 로그 수집 (Wazuh + Elastic)

- siem VM에 **Wazuh all-in-one** 설치(Wazuh manager+indexer+dashboard).
  ```bash
  curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
  sudo bash ./wazuh-install.sh -a    # (설치 시에만 임시 인터넷)
  ```
- 각 대상에 **Wazuh agent** 설치(win-eng/win-biz/mail/sidedoor/weblogic).
- Windows는 Sysmon 로그를, Linux는 syslog/auditd를 Wazuh로 전송(상세는 각 트랙).
- 확인: Kibana(`https://10.20.0.9`) → Agents 전부 Active.

### 2.3 시간 동기화 (상관분석 필수)

- 모든 VM이 **동일 NTP/동일 TZ(Asia/Seoul)**. 시간이 어긋나면 XDR 상관이 깨진다.
  ```bash
  timedatectl set-timezone Asia/Seoul
  ```
- Windows: `w32tm /config /manualpeerlist:10.20.0.1 /syncfromflags:manual /update`

---

## 3. 트랙 00 — 메일 보안 (피싱 진입점)

### 3.1 목표
사칭·피싱 메일을 **SPF/DKIM/DMARC + 본문/URL + 첨부**로 차단·탐지하고, 통과분을 EDR(02)로 넘긴다.

### 3.2 구축 순서
1. **Postfix(SMTP) + Dovecot(IMAP)** 설치, 랩 도메인 `bank.lab`, `partner.lab` 2개 운영.
2. **DNS(bind9 또는 dnsmasq)** 로 랩 내부 도메인 운영(SPF/DKIM/DMARC 레코드 게시 위해 필수).
3. **SPF/DKIM/DMARC** 구성:
   - SPF TXT: `v=spf1 ip4:10.10.0.20 -all`
   - DKIM: OpenDKIM 키 생성 → `default._domainkey` TXT 게시, Postfix milter 연동.
   - DMARC: `_dmarc` TXT: `v=DMARC1; p=reject; rua=mailto:dmarc@bank.lab`
   - (설정 전문: DEMO_01 §A)
4. **Rspamd** 연동(스팸·피싱 스코어링) + **ClamAV**(첨부 스캔) + **YARA**(HTML smuggling 룰).
5. Wazuh agent로 `/var/log/mail.log`, Rspamd 로그 수집.

### 3.3 안전한 공격(테스트) 생성
- **사칭 테스트**: attacker(Kali)에서 `swaks`로 `partner.lab`을 사칭해 `bank.lab` 사용자에게 발송 → DMARC `reject` 동작 확인.
  ```bash
  swaks --to user@bank.lab --from "no-reply@partner.lab" \
        --server 10.10.0.20 --header "Subject: 보험증권 발급 안내" \
        --body "첨부 확인 바랍니다" --attach @eicar.txt
  ```
- **악성 첨부 모사**: 실제 악성코드 대신 **EICAR 표준 테스트 파일**(안전) 사용 → ClamAV 탐지 확인.
- **HTML smuggling 모사**: Base64 인코딩된 더미 페이로드를 가진 HTML 첨부 → YARA 룰로 탐지(실행 페이로드는 무해한 `calc` 흉내 스크립트).

### 3.4 탐지 포인트 & 지표
| 탐지 | 신호 | 도구 |
|---|---|---|
| 사칭 | SPF/DKIM/DMARC 실패 | Postfix/OpenDMARC |
| 피싱 본문 | 긴급성+사칭+단축URL 스코어 | Rspamd (+AI 8장) |
| 악성 첨부 | 시그니처/YARA 매치 | ClamAV/YARA |

- 지표: 사칭 **차단율**, 피싱 **탐지율/오탐율**, 첨부 탐지율. (수집: 9장 하니스)

---

## 4. 트랙 05 — 옆문 / 접근통제

### 4.1 목표
외부 노출 **부속 시스템(옆문)**을 식별하고, **약한 인증/인증 우회**로 침입 시 탐지·격리한다.

### 4.2 구축 순서
1. **취약 옆문 웹앱** 구축(sidedoor VM): 간단한 "대출모집인 조회" 로그인 폼(의도적으로 약한 설정 — 기본 계정 `admin/admin`, MFA 없음, 로그인 실패 제한 없음). 직접 작성 또는 DVWA/OWASP Juice Shop 활용.
2. **자산 식별(ASM)**: attacker에서 **본인 랩 대역만** 스캔.
   ```bash
   nmap -sV -p- 10.10.0.0/24 -oA assets        # 노출 포트/서비스
   nuclei -l targets.txt -t http/              # 노출 취약점(랩 자산 한정)
   ```
3. **접근통제 강화본** 준비: Keycloak로 **MFA + 로그인 실패 잠금** 적용한 버전(비교군용).
4. 로그: 옆문 웹 접근로그 → Wazuh. 비정상 로그인 탐지 룰 작성.

### 4.3 안전한 공격(테스트)
- **약한 인증 침입**: Hydra로 **랩 옆문 로그인**에 사전 대입(본인 자산).
  ```bash
  hydra -l admin -P rockyou-min.txt 10.10.0.30 http-post-form \
    "/login:user=^USER^&pass=^PASS^:Invalid"
  ```
- **측면 이동 모사**: 옆문에서 얻은 계정으로 int망 내부 서비스 접근 시도 → 비업무 시간·새 IP 조건.

### 4.4 탐지 룰(요지, 전문은 DEMO_01 §B)
- 다수 실패 후 성공(무차별 대입 성공): Wazuh rule — 같은 IP 10회 실패 후 200 응답.
- 비정상 로그인: 새 소스IP + 비업무시간(22:00~06:00) + 관리자 계정.
- 대응: 소스IP 차단(iptables), 계정 잠금, 알림.

### 4.5 지표
노출 자산 발견 수, 무차별 대입 탐지율, 비정상 로그인 탐지율/오탐율, MTTD/MTTR.

---

## 5. 트랙 03 — IPS 가상 패치 (롯데카드형)

### 5.1 목표
알려진 취약점(**CVE-2017-10271**)을 **패치 없이 IPS 룰(가상 패치)**로 차단할 수 있음을 룰 ON/OFF로 증명.

### 5.2 구축 순서
1. **vulhub** WebLogic 환경 기동(weblogic VM, 설치 시에만 임시 인터넷):
   ```bash
   git clone https://github.com/vulhub/vulhub
   cd vulhub/weblogic/CVE-2017-10271 && docker compose up -d   # :7001 노출
   ```
2. **Suricata** 설치(ips VM), 미러 트래픽 또는 인라인(NFQUEUE) 구성.
   - IDS 모드(관찰) → 이후 IPS 모드(차단)로 전환해 비교.
3. 룰셋: ET Open 커뮤니티 룰 + **커스텀 룰**(CVE-2017-10271 매칭).
4. Suricata `eve.json` → Wazuh/Elastic 전송.

### 5.3 안전한 공격(트래픽 생성)
- 공개 PoC를 **격리 랩의 자기 서버 대상으로만** 실행해 **익스플로잇 트래픽을 발생**시킨다. PoC 코드를 개선/제작하지 않는다(목적은 탐지).
- 핵심 트래픽 특징: `POST /wls-wsat/CoordinatorPortType` + SOAP XML 내 `java.lang.ProcessBuilder`. → 이 패턴을 룰로 탐지.

### 5.4 실험 설계 (핵심)
| 조건 | 결과 | 의미 |
|---|---|---|
| 룰 OFF | 공격 성공(웹셸/명령실행) | 롯데카드 재현 |
| 룰 ON(가상패치) | 차단 | 가상 패치 효과 증명 |
| 커스텀 룰 vs 기본룰 | 탐지율 비교 | 룰 품질 |
| 정상 트래픽 주입 | 미차단 확인 | 오탐 튜닝 |

- 커스텀 Suricata 룰(요지, 전문 DEMO_01 §C):
  ```
  alert http any any -> $HOME_NET 7001 (msg:"CVE-2017-10271 WebLogic wls-wsat RCE";
    flow:to_server; http.uri; content:"/wls-wsat/"; http.request_body;
    content:"java.lang.ProcessBuilder"; nocase; sid:1000010; rev:1;)
  ```

### 5.5 지표
룰 ON/OFF 침해 성립 여부, 단계별 탐지율(익스플로잇/웹셸/C2), 기본↔커스텀 개선폭, **오탐율**.

---

## 6. 트랙 02 — EDR (건라 랜섬웨어 행위 탐지)

### 6.1 목표
건라의 **행동 순서**(VSS 삭제→대량 암호화→랜섬노트)를 **실제 악성코드 없이** 재현하고, 암호화 이전에 탐지·격리.

### 6.2 구축 순서
1. **Sysmon** 설치(win-eng/win-biz) + 검증된 설정(SwiftOnSecurity/올라프 하트롱 config 기반).
   ```cmd
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
2. **Wazuh agent**가 Sysmon 채널(`Microsoft-Windows-Sysmon/Operational`) 수집.
3. (선택) **Velociraptor**로 프로세스 트리 시각화·헌팅.
4. 건라 탐지용 **Sigma/Wazuh 룰** 적용(VSS 삭제·대량 확장자 변경·랜섬노트).

### 6.3 안전한 행위 에뮬레이션 (실제 암호화 없음)
- **Atomic Red Team** 설치 후 해당 기법만 실행:
  - **T1490**(Inhibit System Recovery): `vssadmin delete shadows` / `wmic shadowcopy delete` — 테스트 볼륨 한정 또는 조회만.
  - **T1486**(Data Encrypted for Impact): Atomic의 **더미 파일 암호화** 테스트(진짜 랜섬웨어 아님).
  ```powershell
  Invoke-AtomicTest T1490 -TestNumbers 1
  Invoke-AtomicTest T1486 -TestNumbers 1   # 더미 대상, 복구 가능
  ```
- **랜섬노트 모사**: 더미 폴더 수백 개에 `R3adm3.txt` 생성 스크립트.
- **확장자 변경 모사**: 더미 파일 다수를 `.CRYPT`로 리네임(실제 암호화 X).
- ⚠️ 스냅샷 복원 가능 상태에서만. 실제 사용자 데이터 대상 금지.

### 6.4 탐지 룰(요지, 전문 DEMO_01 §D)
| 신호 | 탐지 로직 |
|---|---|
| VSS 삭제 | Sysmon EID1: `vssadmin.exe`/`wmic.exe` + cmdline `delete shadows` |
| 대량 확장자 변경 | 단위시간 내 다수 FileCreate/Rename `.CRYPT` |
| 랜섬노트 | 짧은 시간 다수 폴더에 동일 파일명 생성 |
| 프로세스 계보 | browser→installer→powershell 비정상 체인 |

- 대응 자동화: Wazuh active-response로 **프로세스 종료 + 호스트 격리(방화벽 차단)**.

### 6.5 지표
MTTD/MTTR, 단계별 탐지율(어느 단계에서 끊었나), **차단 시점의 '암호화된' 더미파일 수**(피해 대리지표).

---

## 7. 통합 — XDR 상관분석

### 7.1 개념
단일 신호는 약해도, **여러 트랙 신호가 시간·자산으로 이어지면** 공격 확정. 이를 Wazuh/Elastic 상관룰로 구현.

### 7.2 상관 시나리오(킬체인 연결)
```
메일(00) 피싱 탐지  →  win-eng 감염행위(02)  →  int 비정상접근(05/03)  →  VSS삭제(02)
   같은 수신자          같은 호스트              같은 계정/자산            같은 호스트
        └──────────── 동일 엔티티로 묶이면 "확정 공격" 알림 상승 ───────────┘
```

### 7.3 구현
- 공통 필드 정규화: `host.name`, `user.name`, `source.ip`, `@timestamp`.
- Elastic **EQL/상관룰** 또는 Wazuh 복합룰: "동일 host에서 15분 내 (Sysmon 의심 체인) + (Suricata alert)" → severity=critical.
- 경계 방화벽 정책도 이때 조인다: ext→int 최소 포트만 허용(메일·필요한 API), 나머지 차단 → 측면이동 억제.

### 7.4 지표
단독 트랙 대비 **연계 시 탐지 향상폭**, 오탐 감소율, 킬체인 재구성 성공률.

---

## 7.5 SOAR — 자동 대응 오케스트레이션 + AI Slack 알림

### 7.5.1 목표
탐지(XDR)에서 끝내지 않고, **조사→판단→대응→통보**를 자동 플레이북으로 묶는다. 사람은 "승인"만.

### 7.5.2 스택
- **Shuffle**(오픈소스 SOAR): 워크플로우 엔진. Wazuh/Elastic 웹훅 → 플레이북 트리거.
- **TheHive**(케이스 관리) + **Cortex**(분석기): 알럿을 케이스로, IOC를 자동 분석.
- 연동: Wazuh integration → Shuffle webhook → (Cortex 분석) → 대응 액션 → Slack 통보.
  ```bash
  # soar VM
  git clone https://github.com/Shuffle/Shuffle && cd Shuffle && docker compose up -d   # :3443
  ```

### 7.5.3 자동 대응 플레이북 (예: 랜섬웨어 행위 탐지)
```
[트리거] Wazuh: VSS 삭제 탐지(EID1, vssadmin delete shadows)
   │
   ├─(1) 컨텍스트 수집: 호스트·사용자·부모프로세스·최근 메일(00)·IPS알럿(03) 질의
   ├─(2) 위험도 산정: AI(8장) 호출 → "랜섬웨어 확률/근거" 수신
   ├─(3) 자동 봉쇄:
   │       - Wazuh active-response로 호스트 네트워크 격리
   │       - 의심 프로세스 종료, 계정 세션 강제 종료
   │       - 방화벽(gw-fw)에 소스IP 차단 룰 push
   ├─(4) 케이스 생성: TheHive에 타임라인·IOC 등록
   └─(5) 통보: Slack에 AI 요약 카드 전송(아래 7.5.4) + 승인 버튼
```
- **승인 게이트**: 격리는 자동, "계정 영구잠금·서버 셧다운" 같은 고위험 액션은 **Slack 버튼 승인 후** 실행(오탐 대비).

### 7.5.4 AI Slack 훅 (핵심 데모 포인트)
- 흐름: SOAR가 알럿 원문 → **AI(LLM) 요약** → Slack Incoming Webhook으로 전송.
- AI가 생성하는 내용:
  - 한 줄 판정: "🔴 랜섬웨어 의심 (97%)"
  - 근거: "browser→installer→powershell→vssadmin delete shadows 체인, 15분 내 더미 300개 .CRYPT"
  - 영향 자산·추천 대응·관련 킬체인(메일 00→감염 02).
- Slack Block Kit 카드 + **[격리 확인][오탐 처리]** 버튼(Shuffle로 콜백).
- 설정 전문(웹훅 URL·Block Kit JSON·AI 프롬프트): **DEMO_01 §F**.
- 오프라인 랩이면: Slack 대신 **Mattermost(사내 자체호스팅)** 또는 Discord 웹훅으로 대체 가능(동일 구조).

### 7.5.5 지표
- **MTTR 추가 단축**(수동 대비 자동 대응 시간), 자동 봉쇄 성공률, 오탐 시 승인 게이트 작동률.

---

## 8. AI 모듈 (차별화)

### 8.1 적용 지점 3가지
| 지점 | 입력 | 출력 | 모델(제안) |
|---|---|---|---|
| ① 피싱 분류(00) | 메일 본문·헤더·URL 피처 | 피싱 확률 | TF-IDF+LogReg → 또는 소형 LLM |
| ② 알럿 오탐 분류(03) | Suricata alert 피처 | 실공격/오탐 | GBDT(XGBoost) |
| ③ 프로세스 시퀀스 판정(02) | Sysmon 이벤트 시퀀스 | 랜섬웨어 확률 | 시퀀스 특징+분류기/규칙+ML |

### 8.2 데이터
- 랩에서 생성한 **정상/공격 로그**를 라벨링(공격 실행 시점 기록 → 자동 라벨).
- 공개 보강: 피싱은 공개 피싱 코퍼스, IDS는 **CICIDS2017/CSE-CIC-IDS2018**(표준 침입탐지 데이터셋).

### 8.3 평가
- 분류: Precision/Recall/F1, ROC-AUC, **오탐율(FPR)** 강조(금융권은 오탐 민감).
- 룰 단독 vs 룰+AI 비교로 "AI가 실제로 기여하는가" 증명.

### 8.4 LLM 요약(데모 임팩트)
- 프로세스 트리/알럿을 LLM이 **"이건 랜섬웨어, 결정적 증거는 VSS 삭제"**로 자연어 요약 → 분석가 지원. (오프라인이면 소형 로컬 모델, 아니면 데모용 한정)

---

## 8.5 관측성 — Prometheus + Grafana (지표 대시보드)

### 8.5.1 목표
보안 운영 지표(MTTD/MTTR·탐지율·알럿량·대응 현황)를 **실시간 대시보드**로 시각화. 발표의 "숫자"를 여기서 보여준다.

### 8.5.2 스택 구성
```
각 소스 → Exporter/메트릭 → Prometheus(수집) → Grafana(시각화)
                                   │
                                   └→ Alertmanager → SOAR/Slack(임계 초과 시)
```
- **Prometheus**(obsv VM): 스크레이프 대상 = node_exporter(각 VM 자원), 커스텀 exporter(보안 지표).
- **Grafana**: 대시보드. Prometheus + **Elasticsearch(Wazuh 인덱스)** 둘 다 데이터소스로 연결.
- **Alertmanager**: 임계값 초과(예: 랜섬웨어 알럿 발생, MTTR 급증) → webhook로 SOAR/Slack.
  ```bash
  # obsv VM
  docker compose up -d prometheus grafana alertmanager node-exporter   # compose: DEMO_01 §G
  ```

### 8.5.3 보안 지표를 메트릭으로 노출 (커스텀 exporter)
- 작은 Python exporter가 Wazuh/Elastic를 쿼리해 Prometheus 포맷으로 노출:
  - `sec_alerts_total{track="02",severity="critical"}`
  - `sec_mttd_seconds{scenario="ransomware"}` / `sec_mttr_seconds{...}`
  - `sec_phishing_blocked_ratio`, `sec_ips_falsepositive_ratio`
  - `sec_encrypted_dummy_files`(피해 대리지표)
- 평가 하니스(9장)가 각 실험 종료 시 이 값을 push/expose → Grafana에 군(A~F)별 비교.

### 8.5.4 Grafana 대시보드 패널(권장)
| 패널 | 내용 |
|---|---|
| 킬체인 진행 | ATT&CK 단계별 탐지 현황(히트맵) |
| MTTD/MTTR | 시나리오별 막대 + A~F 비교 |
| 알럿 추이 | 트랙별 알럿량 시계열 |
| 피해 대리지표 | 암호화 더미파일 수(군별) |
| 오탐율 | 트랙별 FPR 게이지 |
| 자원 | 각 VM CPU/RAM(node_exporter) |

> 역할 분담: **Prometheus/Grafana(메트릭·대시보드)** vs **Wazuh/Elastic(이벤트·로그·탐지)** — 둘은 상호보완. 전자는 "추세·KPI", 후자는 "개별 사건·조사".

### 8.5.5 지표(메타)
대시보드 구축 자체가 산출물. 발표 시 "A→F 개선"을 이 화면으로 1분 안에 증명.

---

## 9. 평가 하니스 (비교 실험)

### 9.1 비교군
| 군 | 구성 |
|---|---|
| A | 경계(망분리)만 |
| B | +메일보안(00) |
| C | +접근통제(05) |
| D | +IPS(03) |
| E | +EDR(02) |
| F | 전체+XDR/AI |

### 9.2 절차(각 군 공통)
1. 스냅샷 복원(클린 상태).
2. 해당 군의 방어만 활성화.
3. **표준 공격 플레이북** 실행(아래 10.2 킬체인) — 매번 동일.
4. 로그·타임스탬프 수집 → 지표 산출.
5. 결과 기록 후 롤백.

### 9.3 공통 지표 수집
- **MTTD** = 최초 탐지 시각 − 공격 시작 시각.
- **MTTR** = 차단/격리 시각 − 공격 시작 시각.
- **단계별 탐지율** = 탐지된 ATT&CK 단계 수 / 전체 단계 수.
- **피해 대리지표** = 암호화된 더미파일 수, 웹셸 성립 여부, 옆문 침입 성립 여부, 유출 모사 바이트.
- **오탐율** = 정상 트래픽/메일/로그인 중 오탐 비율.
- 수집 자동화: Elastic에 공격 시작 마커 이벤트를 심고, 쿼리로 Δt 계산(스크립트는 DEMO_01 §E).

### 9.4 기대 결과(가설)
A→F로 갈수록 MTTD/MTTR 감소, 단계별 탐지율 상승, 피해 대리지표 감소. **F에서 암호화 이전 차단** 달성이 핵심 메시지.

---

## 10. 데모 시나리오 (발표용)

### 10.1 스토리라인 (하나의 공격, 전 구간)
"임원에게 **보험증권 사칭 피싱 메일**(00) 도착 → 첨부 클릭으로 win-eng 감염 → 공격자는 외부 **옆문**(05)으로도 진입 시도 → **WebLogic 취약점**(03)으로 서버 장악 시도 → 내부에서 **랜섬웨어 행위**(02) 개시(VSS 삭제) → **XDR/AI**(7·8)가 전 신호를 엮어 **암호화 직전 차단·격리**."

### 10.2 표준 킬체인 플레이북 (평가·데모 공용)
```
T1566 피싱 메일 발송(swaks)                → 00 탐지
T1204 첨부 실행(더미)                      → 02 프로세스 체인 탐지
T1190 WebLogic 익스플로잇 트래픽            → 03 IPS 탐지/차단
T1110 옆문 무차별 대입(hydra)              → 05 탐지
T1021 측면 이동 시도                        → 05/07 탐지
T1490 VSS 삭제(Atomic)                     → 02 탐지 ★차단 분기
T1486 더미 암호화(Atomic)                   → 02 안티랜섬웨어(미도달이 목표)
```

### 10.3 시연 순서(요약, 상세 멘트는 DEMO_02)
1. **"막기 전"**(A군): 공격 쭉 성공 → 더미 다수 `.CRYPT` → "이게 서울보증 64시간."
2. **"막은 후"**(F군): 같은 공격 → VSS 삭제 시점에 **SOAR 자동 격리** → 암호화 0건.
3. **XDR 화면**: 메일→감염→VSS 삭제가 한 타임라인으로 연결.
4. **AI Slack 카드**: 실시간으로 "🔴 랜섬웨어 97%, 근거 VSS 삭제" 카드가 Slack에 뜨고 **[격리 확인]** 버튼 → 클릭하면 봉쇄 완료. (관객 눈앞에서)
5. **Grafana 대시보드**: A vs F의 MTTD/MTTR·피해 막대·킬체인 히트맵을 한 화면에.
6. **마무리**: "탐지(XDR)→판단(AI)→대응(SOAR)→통보(Slack)→가시화(Grafana)"가 1분 내 자동으로 돈다는 것을 강조.

---

## 11. 역할 분담 (팀)

| 트랙 | 담당(예) | 산출물 |
|---|---|---|
| 00 메일 | (메일서버 원담당) | 메일서버+인증+탐지 |
| 05 옆문 | | 자산식별+NAC+탐지룰 |
| 03 IPS | | vulhub+Suricata+룰 |
| 02 EDR | | Sysmon+Wazuh+에뮬+룰 |
| 07/08 XDR·AI | | 상관룰+AI모델 |
| 7.5 SOAR·Slack | | Shuffle 플레이북+AI Slack 훅+TheHive |
| 8.5 관측성 | | Prometheus exporter+Grafana 대시보드 |
| 09/10 평가·발표 | | 하니스+대시보드+대본 |

> 공통(네트워크·SIEM)은 1~2주차에 **함께** 세팅 후 분화. SOAR·관측성은 XDR이 선 것(7장) 위에 얹으므로 7주차 집중.

---

## 12. 일정 (8주 통합)

| 주 | 공통 | 트랙 |
|---|---|---|
| 1 | 토폴로지·격리망·SIEM | 전원 |
| 2 | 로그수집 검증 | 00 메일 |
| 3 | | 05 옆문/접근통제 |
| 4 | | 03 IPS |
| 5–6 | | 02 EDR |
| 7 | XDR 상관 + AI + SOAR(7.5) + 관측성(8.5) | 07/08/7.5/8.5 |
| 8 | 평가(A~F)+Grafana 대시보드+발표 | 09/10 |

---

## 13. 트러블슈팅 & 체크리스트

- [ ] 모든 VM 인터넷 차단 확인(`ping 8.8.8.8` 실패).
- [ ] 전 VM 시간 동기화(상관분석 전제).
- [ ] Wazuh agent 전부 Active.
- [ ] 공격 전 **스냅샷**, 공격 후 **롤백**.
- [ ] EICAR·더미만 사용(실악성코드 금지).
- [ ] 스캔/공격은 **본인 랩 대역만**.
- 흔한 문제: Suricata가 트래픽 못 봄 → 미러포트/HOME_NET 확인. Sysmon 로그 안 옴 → 채널 구독·Wazuh `localfile` 설정. DMARC 미동작 → DNS 레코드·milter 순서.

## 14. 주의(법/윤리)
- 모든 공격 기법은 **격리 랩·교육 목적 한정**. 외부 시스템·실제 기관 대상 금지.
- 사고 사례 수치·날짜는 공개 보도 기반 → 발표 전 원문 재확인.
- 비공개(자문) 사례는 익명 처리.
