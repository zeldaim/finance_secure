# 트랙 00 — 메일 보안 구축본 (실행·검증 포함)

> 공격 체인의 진입점(피싱 메일)을 막는 트랙. **탐지 엔진은 실제 실행·검증 완료**, 메일서버 스택은 완성 config 제공(기동은 Docker 호스트 필요).
> 격리 랩/교육용. 실제 악성코드·외부 발송 금지.

---

## 1. 구성

```
메일보안_구축본/
├── detector/              ← 피싱/악성 탐지 엔진 (순수 Python, 검증됨)
│   ├── maildet.py         ·  .eml 분석 → 점수화 → pass/quarantine/reject
│   └── test_maildet.py    ·  회귀 테스트 (기대값 단언)
├── samples/               ← 검증용 샘플 메일 5종 + SPF 정책
├── mailstack/             ← 메일서버 스택 (docker-mailserver)
│   ├── docker-compose.yml ·  Postfix+Dovecot+Rspamd+ClamAV+DKIM/DMARC
│   ├── mailserver.env     ·  보안기능 활성 설정
│   ├── dns-records.txt    ·  SPF/DKIM/DMARC 존 레코드
│   └── setup-notes.md     ·  기동·테스트 절차
└── rules/
    └── html_smuggling.yar ← HTML smuggling / EICAR YARA 룰
```

## 2. 검증 상태 (정직하게)

| 구성요소 | 상태 | 검증 방법 |
|---|---|---|
| `maildet.py` 탐지 로직 | ✅ **실행·검증 완료** | 아래 §3 출력. test_maildet.py 5/5 PASS (exit 0) |
| 중복 집계 버그 | ✅ **발견·수정** | bit.ly 이중 집계 → dedup 적용(03: 26→23) |
| 메일서버 스택(compose/env/dns) | ⚠️ **구성 완성, 기동 미검증** | 이 환경에 Docker 없음 → 사용자 랩에서 `docker compose up` 필요 |
| YARA 룰 | ⚠️ **작성 완료, yara 엔진 미설치** | 로직은 maildet의 html_smuggling 탐지로 교차검증됨 |

> 솔직히: 메일서버 **기동 자체**는 Docker가 있는 랩에서 돌려야 확인됩니다. 다만 그 앞단 **탐지 판단 로직**은 여기서 실제 샘플로 돌려 검증했습니다.

## 3. 탐지 엔진 실행 결과 (재현 가능)

```
$ cd detector
$ PYTHONUTF8=1 python maildet.py --selftest
```
실제 출력:
```
[ok] [PASS]       score=0   01_legit.eml            (no findings)
[!]  [QUARANTINE] score=14  02_spoof_dmarc_fail.eml  dmarc_fail(+8), display_name_spoof(+6)
[X]  [REJECT]     score=23  03_phish_lookalike.eml   dmarc_fail, urgency, credential_lure,
                                                      url_text_mismatch(kbcard→bit.ly), shortener_url
[!]  [QUARANTINE] score=7   04_html_smuggling.eml    html_smuggling(tracking.html)
[X]  [REJECT]     score=21  05_eicar_attach.eml      dangerous_attach, double_extension, eicar
```
회귀 테스트:
```
$ PYTHONUTF8=1 python test_maildet.py
5 passed, 0 failed   (exit 0)
```

## 4. 탐지 엔진이 보는 신호 (가중치)

| 코드 | 의미 | 가중치 |
|---|---|---|
| dmarc_fail | From 도메인 정렬 실패 + SPF fail | 8 |
| display_name_spoof | 표시이름=기관, 도메인=무관(사칭) | 6 |
| lookalike_domain | 유사 도메인(rn/0 치환, 과도한 하이픈) | 5 |
| url_text_mismatch | 링크 텍스트 ≠ 실제 href 도메인 | 5 |
| html_smuggling | Blob+atob+강제저장 | 7 |
| eicar | EICAR 악성 모사 | 10 |
| double_extension | invoice.pdf.exe | 5 |
| dangerous_attach | .exe/.js/.hta ... | 6 |
| urgency / credential_lure | 긴급성 / 자격증명 유도 | 3 / 4 |
| ip_literal_url / punycode_url / shortener_url | URL 위험 신호 | 4 / 4 / 3 |

판정: score ≥ 15 **reject**, ≥ 6 **quarantine**, else **pass**. (임계값은 WEIGHTS로 튜닝)

## 5. 튜닝 메모 (운영 전 고려)

- `02_spoof`는 14점 → **quarantine**. DMARC `p=reject` 정책이면 **메일서버(Rspamd/OpenDMARC)가 SMTP 단에서 먼저 거부**하므로 실제로는 이중 방어. detector는 보조.
- 임계값·가중치는 **오탐(정상 메일 차단)**이 금융권에서 가장 치명적 → 운영 데이터로 재튜닝 필요.
- AI 확장(런북 8장): 이 룰 점수를 피처로 추가해 ML 분류기와 앙상블 가능.

## 6. 다음 단계

1. Docker 랩에서 `mailstack` 기동 → swaks 테스트(setup-notes §5).
2. Rspamd history ↔ maildet 판정 **교차 비교**(일치율 측정).
3. Wazuh로 mail.log 수집 → 런북 XDR(7장)·SOAR(7.5)로 "피싱 탐지 → 자동 격리" 연결.
4. 샘플을 50~100건으로 늘려 탐지율/오탐율 지표화(런북 9장 하니스).

## 7. 사용법 요약
```bash
# 단건 분석
python detector/maildet.py samples/03_phish_lookalike.eml
# JSON 출력(SOAR 연동용)
python detector/maildet.py samples/03_phish_lookalike.eml --json
# SPF 정책 적용
python detector/maildet.py mail.eml --spf-policy samples/spf_policy.json
# 전체 자체검증
python detector/maildet.py --selftest
# 회귀 테스트
python detector/test_maildet.py
```
> Windows 콘솔에서 한글 깨지면 `set PYTHONUTF8=1` 후 실행.
