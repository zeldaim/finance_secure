# 메일 스택 기동 절차 (setup)

> 전제: 격리 랩의 리눅스 호스트, Docker + docker compose 설치됨. 인터넷과 분리된 내부망.
> 이미지/패키지 최초 pull 시에만 임시 인터넷 → 이후 차단.

## 1. 계정 생성
```bash
# docker-mailserver 헬퍼(setup)로 사용자 추가
docker compose up -d
docker exec -ti mailserver setup email add user@bank.lab 'Passw0rd!'
docker exec -ti mailserver setup email add security@bank.lab 'Passw0rd!'
docker exec -ti mailserver setup email list
```

## 2. DKIM 키 생성 + DNS 레코드
```bash
docker exec -ti mailserver setup config dkim domain bank.lab
# 생성물: config/opendkim/keys/bank.lab/mail.txt (DNS에 게시할 공개키)
cat docker-data/dms/config/opendkim/keys/bank.lab/mail.txt
```
→ 출력된 TXT를 DNS(bind9)에 게시. `dns-records.txt` 참고.

## 3. DNS(bind9) 레코드 — dns-records.txt 적용
SPF / DKIM / DMARC 3종을 `bank.lab` 존에 추가 후 `rndc reload`.

## 4. 기동 확인
```bash
docker compose ps                      # healthy 확인
docker exec mailserver ss -lntp        # 25/587/993 리슨
docker exec mailserver rspamc stat     # Rspamd 동작
docker exec mailserver clamdscan --version
```

## 5. 테스트 (attacker VM에서 swaks)
```bash
# (A) 정상 메일 - 통과 기대
swaks --to user@bank.lab --from security@bank.lab --server 10.10.0.20 \
      --header "Subject: 테스트" --body "정상 본문"

# (B) 사칭(SPF/DMARC fail) - 거부/격리 기대
swaks --to user@bank.lab --from "no-reply@partner.lab" --server 10.10.0.20 \
      --header "Subject: [보험증권] 발급 안내" --body "확인 바랍니다"

# (C) EICAR 첨부 - ClamAV 차단 기대
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
swaks --to user@bank.lab --from a@partner.lab --server 10.10.0.20 \
      --header "Subject: 청구서" --attach @eicar.txt
```

## 6. 로그/탐지 확인
```bash
docker exec mailserver tail -f /var/log/mail/mail.log        # Postfix/정책
docker exec mailserver rspamc history                        # Rspamd 판정
# Wazuh agent가 /var/log/mail/ 를 수집하도록 설정(런북 §2.2)
```

## 7. maildet.py 연계 (보조 분석/교육용)
- Rspamd가 1차 운영 탐지. `maildet.py`는 격리된 .eml을 **사후 분석·설명**하고 점수 근거를 보여주는 보조 도구.
- 격리 메일 덤프 → `python ../detector/maildet.py quarantined.eml` 로 근거 확인.
- (심화) Postfix `content_filter` 또는 milter로 인라인 연동 가능하나, 운영 탐지는 Rspamd 권장.

## 기대 결과 요약
| 테스트 | 동작 | 근거 |
|---|---|---|
| 정상 | 수신함 | SPF pass, 점수 낮음 |
| 사칭 | 거부/Junk | SPF/DMARC fail |
| EICAR | 차단 | ClamAV 시그니처 |
