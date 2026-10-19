# DEMO 설정파일 모음 (복붙용)
# 통합 랩 구축에 쓰는 config / 탐지룰 / 스크립트 전문

> 런북(DEMO_00)에서 §A~§G로 참조. 모두 **격리 랩 교육용**. 값(IP·도메인·토큰)은 환경에 맞게 치환.
> ⚠️ 실제 악성코드·외부 발송 금지. EICAR·더미만 사용.

## 목차
- §A 메일 보안(00): SPF/DKIM/DMARC, Rspamd, YARA
- §B 옆문/접근통제(05): Wazuh 룰, nmap/nuclei
- §C IPS(03): Suricata 커스텀 룰, 실행
- §D EDR(02): Sysmon, Sigma/Wazuh 룰, 에뮬 스크립트, active-response
- §E 평가 하니스(09): 마커·지표 수집 스크립트
- §F SOAR + AI Slack 훅(7.5): Shuffle 플레이북, Slack Block Kit, AI 프롬프트
- §G 관측성(8.5): Prometheus/Grafana compose, exporter, alert rule

---

## §A 메일 보안 (트랙 00)

### A-1. DNS 레코드 (bind9 zone `bank.lab`)
```dns
bank.lab.            IN TXT "v=spf1 ip4:10.10.0.20 -all"
default._domainkey   IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSq...(공개키)..."
_dmarc               IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@bank.lab; fo=1"
```

### A-2. Postfix main.cf (발췌)
```ini
myhostname = mail.bank.lab
mydomain   = bank.lab
# milter: OpenDKIM(8891) + OpenDMARC(8893) + Rspamd(11332)
smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893, inet:127.0.0.1:11332
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination
```

### A-3. OpenDMARC 정책
```ini
# /etc/opendmarc.conf
AuthservID mail.bank.lab
RejectFailures true      # DMARC fail 시 거부(데모에선 quarantine→reject로 단계 시연)
Syslog true
```

### A-4. Rspamd 피싱 가중치 (local.d/)
```ucl
# /etc/rspamd/local.d/actions.conf
reject   = 15;
add_header = 6;     # 의심 → 헤더 태깅(격리 폴더로)
greylist = 4;
# phishing 모듈 활성 (local.d/phishing.conf): check_urls + redirector
```

### A-5. YARA — HTML smuggling 모사 탐지
```yara
rule HTML_Smuggling_Lab {
  meta: desc = "lab: base64 blob + msSaveOrOpenBlob pattern"
  strings:
    $a = "application/octet-stream" nocase
    $b = "msSaveOrOpenBlob" nocase
    $c = /atob\(["'][A-Za-z0-9+\/=]{200,}/
  condition: 2 of them
}
```

### A-6. 안전 테스트 발송 (attacker)
```bash
# 사칭(DMARC reject 확인용) — 랩 내부에서만
swaks --to user@bank.lab --from "no-reply@partner.lab" --server 10.10.0.20 \
  --header "Subject: [보험증권] 발급 안내" --body phishing_body.txt --attach @eicar.txt
# eicar.txt 내용(표준 안전 테스트 문자열):
# X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

---

## §B 옆문 / 접근통제 (트랙 05)

### B-1. 자산 식별 (본인 랩 대역만)
```bash
nmap -sV -p- --open 10.10.0.0/24 -oA lab_assets
nuclei -l lab_targets.txt -t http/ -severity medium,high,critical -o nuclei_out.txt
```

### B-2. Wazuh 룰 — 무차별 대입 성공 + 비정상 로그인
```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="sidedoor,authentication,">
  <rule id="100200" level="5">
    <decoded_as>json</decoded_as>
    <field name="app">sidedoor</field>
    <field name="status">fail</field>
    <description>Sidedoor 로그인 실패</description>
  </rule>
  <!-- 같은 IP 10회 실패(프리퀀시) -->
  <rule id="100201" level="10" frequency="10" timeframe="120">
    <if_matched_sid>100200</if_matched_sid>
    <same_source_ip/>
    <description>Sidedoor 무차별 대입 의심(10 fails/120s)</description>
    <mitre><id>T1110</id></mitre>
  </rule>
  <!-- 실패 폭주 직후 성공 = 대입 성공 -->
  <rule id="100202" level="12">
    <if_sid>100201</if_sid>
    <field name="status">success</field>
    <description>무차별 대입 성공 가능성(옆문 침입)</description>
  </rule>
  <!-- 비업무시간 관리자 로그인 -->
  <rule id="100203" level="10">
    <field name="app">sidedoor</field>
    <field name="user">admin</field>
    <field name="status">success</field>
    <time>10:00 pm - 6:00 am</time>
    <description>비업무시간 관리자 로그인(옆문)</description>
  </rule>
</group>
```

### B-3. 안전 테스트 (본인 옆문)
```bash
hydra -l admin -P pass_small.txt 10.10.0.30 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials" -t 4
```

---

## §C IPS (트랙 03)

### C-1. vulhub 기동
```bash
cd vulhub/weblogic/CVE-2017-10271 && docker compose up -d   # http://10.10.0.40:7001
```

### C-2. Suricata 커스텀 룰
```
# /etc/suricata/rules/local.rules
alert http any any -> $HOME_NET 7001 ( \
  msg:"LAB CVE-2017-10271 WebLogic wls-wsat RCE attempt"; \
  flow:established,to_server; http.method; content:"POST"; \
  http.uri; content:"/wls-wsat/"; nocase; \
  http.request_body; content:"java.lang.ProcessBuilder"; nocase; \
  classtype:web-application-attack; sid:1000010; rev:1; \
  metadata:mitre_technique T1190; )

# 웹셸 흔적(업로드 후 접근) — 후속 단계 탐지
alert http any any -> $HOME_NET 7001 ( \
  msg:"LAB possible webshell access"; flow:to_server; \
  http.uri; pcre:"/\.(jsp|jspx)\?(cmd|exec)=/i"; \
  sid:1000011; rev:1; )
```

### C-3. IDS→IPS 전환
```yaml
# /etc/suricata/suricata.yaml (인라인 NFQUEUE)
# af-packet(관찰) → nfqueue(차단)로 전환
nfqueue:
  mode: accept
# iptables로 7001 트래픽을 큐로
```
```bash
iptables -I FORWARD -p tcp --dport 7001 -j NFQUEUE --queue-num 0
suricata -q 0 -c /etc/suricata/suricata.yaml   # IPS 모드
# 룰 drop으로 바꾸면 차단: 'alert' → 'drop'
```

### C-4. 오탐 튜닝 체크
- 정상 요청 코퍼스(정상 SOAP/HTTP) 재생 → `sid:1000010` 매치 0 확인.
- 매치되면 `content` 범위/`http.request_body` 길이 제한으로 좁힘.

---

## §D EDR (트랙 02)

### D-1. Sysmon 설정 (핵심 발췌; 베이스=SwiftOnSecurity)
```xml
<Sysmon schemaversion="4.90">
 <EventFiltering>
  <!-- 프로세스 생성 전부(계보 추적) -->
  <RuleGroup groupRelation="or">
   <ProcessCreate onmatch="exclude"></ProcessCreate>
  </RuleGroup>
  <!-- VSS/복구 무력화 도구 집중 -->
  <RuleGroup groupRelation="or">
   <ProcessCreate onmatch="include">
     <Image condition="end with">vssadmin.exe</Image>
     <Image condition="end with">wmic.exe</Image>
     <Image condition="end with">wbadmin.exe</Image>
     <Image condition="end with">bcdedit.exe</Image>
   </ProcessCreate>
  </RuleGroup>
  <FileCreate onmatch="include">
     <TargetFilename condition="end with">.CRYPT</TargetFilename>
     <TargetFilename condition="end with">R3adm3.txt</TargetFilename>
  </FileCreate>
 </EventFiltering>
</Sysmon>
```

### D-2. Wazuh 룰 — 건라 행위
```xml
<group name="sysmon,ransomware,">
  <!-- VSS 삭제 -->
  <rule id="100300" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">vssadmin.exe|wmic.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(delete|resize).*shadow</field>
    <description>랜섬웨어 전조: 볼륨 섀도우(VSS) 삭제 시도</description>
    <mitre><id>T1490</id></mitre>
  </rule>
  <!-- 대량 .CRYPT 생성(프리퀀시) -->
  <rule id="100301" level="13" frequency="50" timeframe="60">
    <if_group>sysmon_event_11</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">\.CRYPT$</field>
    <same_source_ip/>
    <description>랜섬웨어: 단시간 대량 .CRYPT 생성(암호화 진행)</description>
    <mitre><id>T1486</id></mitre>
  </rule>
  <!-- 랜섬노트 반복 -->
  <rule id="100302" level="12" frequency="10" timeframe="60">
    <if_group>sysmon_event_11</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">R3adm3\.txt$</field>
    <description>랜섬웨어: 랜섬노트 반복 생성</description>
  </rule>
</group>
```

### D-3. Sigma (이식용, 선택)
```yaml
title: Ransomware VSS Deletion (lab)
logsource: {product: windows, service: sysmon}
detection:
  sel:
    EventID: 1
    Image|endswith: ['\vssadmin.exe','\wmic.exe']
    CommandLine|contains|all: ['shadow','delete']
  condition: sel
level: high
tags: [attack.t1490]
```

### D-4. 안전한 행위 에뮬레이션 (실제 암호화 없음)
```powershell
# Atomic Red Team
Install-Module Invoke-AtomicRedTeam -Scope CurrentUser
Invoke-AtomicTest T1490 -TestNumbers 1          # VSS (스냅샷 복원 가능 상태에서)
# 더미 암호화/랜섬노트 모사 (직접 스크립트, 진짜 악성코드 아님)
$d="C:\lab\dummy"; 1..300 | % { "x" | Out-File "$d\f$_.txt" }
Get-ChildItem $d\*.txt | Rename-Item -NewName { $_.Name -replace '\.txt$','.CRYPT' }
1..50 | % { "contact qTox..." | Out-File "$d\sub$_\R3adm3.txt" -Force }
```

### D-5. active-response (자동 격리)
```xml
<!-- ossec.conf: VSS 삭제(100300) 시 호스트 격리 -->
<command>
  <name>isolate-host</name>
  <executable>isolate-host.sh</executable>
</command>
<active-response>
  <command>isolate-host</command>
  <location>local</location>
  <rules_id>100300</rules_id>
</active-response>
```
```bash
# isolate-host.sh (에이전트측): 업무망 외 통신 차단
#!/bin/sh
netsh advfirewall firewall add rule name="LAB-ISOLATE" dir=out action=block remoteip=any
# (Windows는 netsh; Linux면 iptables DROP)
```

---

## §E 평가 하니스 (9장)

### E-1. 공격 시작 마커 (상관 기준점)
```bash
# 공격 플레이북 시작 시 Elastic에 마커 색인
curl -XPOST "http://10.20.0.9:9200/lab-markers/_doc" -H 'Content-Type: application/json' -d'
{ "@timestamp":"'"$(date -u +%FT%TZ)"'", "event":"attack_start", "scenario":"ransomware", "group":"F" }'
```

### E-2. MTTD/MTTR 산출 (의사코드)
```python
start = query_marker("attack_start", group)              # 공격 시작
detect = first_alert_ts(group, scenario)                 # 최초 탐지
respond = first_response_ts(group, scenario)             # 격리/차단
mttd = detect - start; mttr = respond - start
push_metric("sec_mttd_seconds", mttd, {"group":group,"scenario":scenario})
push_metric("sec_mttr_seconds", mttr, {...})
```

### E-3. 피해 대리지표
```powershell
(Get-ChildItem C:\lab\dummy -Recurse -Filter *.CRYPT).Count   # 암호화된 더미 수
```

---

## §F SOAR + AI Slack 훅 (7.5)

### F-1. Shuffle 플레이북 (노드 흐름, 의사정의)
```
Trigger: Webhook  (Wazuh integration → POST /api/v1/hooks/<id>)
  ↓
Node1 Enrich:  Elastic 쿼리(host,user,parent,최근 메일00,IPS03 alert)
  ↓
Node2 AI Verdict:  HTTP POST → AI 요약 엔드포인트(F-3)  → {verdict, confidence, reason}
  ↓
Node3 Contain(auto): Wazuh active-response(격리) + gw-fw iptables block(source.ip)
  ↓
Node4 Case:  TheHive create case(title, IOC, timeline)
  ↓
Node5 Notify:  Slack webhook(Block Kit, F-2) with buttons
  ↓
(Callback) Node6:  버튼 '오탐처리' → 격리 롤백 / '격리확인' → 고위험 액션 승인
```

### F-2. Slack Block Kit 카드 (AI 요약 주입)
```json
{
  "blocks": [
    {"type":"header","text":{"type":"plain_text","text":"🔴 랜섬웨어 의심 (97%)"}},
    {"type":"section","text":{"type":"mrkdwn","text":
      "*호스트*: win-eng (10.20.0.50)\n*사용자*: eng01\n*근거*: {{ai_reason}}\n*킬체인*: 피싱(00)→감염(02)→VSS삭제(T1490)"}},
    {"type":"section","text":{"type":"mrkdwn","text":"*자동대응*: 호스트 격리 완료 · 소스IP 차단"}},
    {"type":"actions","elements":[
      {"type":"button","style":"primary","text":{"type":"plain_text","text":"격리 확인"},"value":"confirm"},
      {"type":"button","style":"danger","text":{"type":"plain_text","text":"오탐 처리(롤백)"},"value":"fp"}
    ]}
  ]
}
```
```bash
# 전송 (Shuffle Node5 또는 테스트)
curl -XPOST -H 'Content-type: application/json' --data @card.json \
  https://hooks.slack.com/services/XXXX/YYYY/ZZZZ
# 오프라인 랩: Mattermost/Discord incoming webhook으로 URL만 교체
```

### F-3. AI 요약 엔드포인트 프롬프트 (LLM)
```
[System] 너는 SOC 분석 보조다. 주어진 보안 이벤트(JSON)를 보고
1) verdict(malicious/benign/suspicious), 2) confidence(0-100),
3) reason(한국어 1~2문장, 결정적 증거 명시), 4) recommended_action
을 JSON으로만 답하라. 과장 금지, 근거는 이벤트에 있는 것만.
[User] {events_json}   # Sysmon 체인 + IPS/메일 알럿 + 자산 컨텍스트
```
- 출력 예: `{"verdict":"malicious","confidence":97,"reason":"browser→installer→powershell→vssadmin delete shadows 체인 후 60초 내 .CRYPT 300건","recommended_action":"isolate host, reset eng01"}`
- 오프라인: 소형 로컬 모델(예: 자체호스팅) 또는 규칙 기반 폴백(핵심 신호 가중합)로 confidence 산출.

---

## §G 관측성 — Prometheus + Grafana (8.5)

### G-1. docker-compose (obsv VM)
```yaml
services:
  prometheus:
    image: prom/prometheus:v2.53.0
    ports: ["9090:9090"]
    volumes: ["./prometheus.yml:/etc/prometheus/prometheus.yml"]
  grafana:
    image: grafana/grafana:11.1.0
    ports: ["3000:3000"]
  alertmanager:
    image: prom/alertmanager:v0.27.0
    ports: ["9093:9093"]
    volumes: ["./alertmanager.yml:/etc/alertmanager/alertmanager.yml"]
  node-exporter:
    image: prom/node-exporter:v1.8.1
    ports: ["9100:9100"]
  sec-exporter:         # 커스텀 보안지표 exporter(G-3)
    build: ./sec-exporter
    ports: ["9110:9110"]
```

### G-2. prometheus.yml
```yaml
global: { scrape_interval: 15s }
scrape_configs:
  - job_name: node
    static_configs: [{ targets: ['10.20.0.6:9100','10.20.0.9:9100','10.20.0.50:9100'] }]
  - job_name: security
    static_configs: [{ targets: ['10.20.0.6:9110'] }]
alerting:
  alertmanagers: [{ static_configs: [{ targets: ['10.20.0.6:9093'] }] }]
rule_files: ['alert.rules.yml']
```

### G-3. 커스텀 보안 exporter (Python, 요지)
```python
# Wazuh/Elastic 쿼리 → Prometheus 포맷 노출 (:9110/metrics)
from prometheus_client import start_http_server, Gauge
import time
g_mttd = Gauge('sec_mttd_seconds','MTTD',['scenario','group'])
g_mttr = Gauge('sec_mttr_seconds','MTTR',['scenario','group'])
g_enc  = Gauge('sec_encrypted_dummy_files','encrypted dummies',['group'])
g_fp   = Gauge('sec_ips_falsepositive_ratio','IPS FPR',['track'])
g_phish= Gauge('sec_phishing_blocked_ratio','phishing blocked',['track'])
def refresh():
    # elastic_query(...) 결과로 set
    g_mttd.labels('ransomware','F').set(query_mttd('F'))
    # ...
if __name__ == "__main__":
    start_http_server(9110)
    while True: refresh(); time.sleep(15)
```

### G-4. alert.rules.yml (임계 → SOAR/Slack)
```yaml
groups:
- name: security
  rules:
  - alert: RansomwareSignal
    expr: increase(sec_alerts_total{track="02",severity="critical"}[1m]) > 0
    labels: {severity: critical}
    annotations: {summary: "랜섬웨어 전조 탐지 — SOAR 플레이북 트리거"}
  - alert: MTTRDegraded
    expr: sec_mttr_seconds{scenario="ransomware"} > 300
    labels: {severity: warning}
    annotations: {summary: "대응 지연(MTTR>5m)"}
```

### G-5. alertmanager.yml (webhook → Shuffle)
```yaml
route: { receiver: soar }
receivers:
- name: soar
  webhook_configs:
    - url: 'http://10.20.0.7:3443/api/v1/hooks/prometheus'
```

### G-6. Grafana 데이터소스
- Prometheus: `http://10.20.0.6:9090`
- Elasticsearch(Wazuh): `https://10.20.0.9:9200` (인덱스 `wazuh-alerts-*`)
- 대시보드 패널: 런북 §8.5.4 표 참조(킬체인 히트맵·MTTD/MTTR·오탐율 게이지·피해 막대).

---

## 부록 — 안전/정리 체크
- [ ] 모든 설정의 IP/도메인/토큰을 **자기 랩 값**으로 치환.
- [ ] Slack 웹훅 URL·AI 키는 **깃에 커밋 금지**(.env/secret).
- [ ] 공격 전 스냅샷 → 실험 → 롤백.
- [ ] Atomic T1486은 **더미 대상·복원 가능** 상태에서만.
- [ ] 발표 자료에 실제 회사명/비공개 사례 미기재.
