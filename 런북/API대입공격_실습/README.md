# API 대입 조회 공격 — 실습 랩 (2026 신한은행 사고 재현·방어)

> 제안서 `07_제안서_신한은행_API대입공격_실시간탐지.md`의 실증 랩.
> 2026년 신한은행 2.5만 명 유출 사고의 핵심(**인가 검증 누락 IDOR + 자동 대입 조회**)을
> **안전한 로컬 환경**에서 재현하고, **예방·탐지·대응** 3층 방어의 효과를 숫자로 측정한다.

## ⚠️ 안전 수칙 (반드시 지킬 것)

- 모든 실행은 **로컬(127.0.0.1)**, **본인이 띄운 랩**에만. 실제 금융사·외부 시스템 금지.
- 데이터는 전부 **합성(가짜)**. 주민번호/CI는 `000000-…`, `CI-TEST-…` 같은 가짜 패턴.
- 공격 스크립트(`attack/replay.py`)는 대상 주소가 `127.0.0.1`로 하드코딩돼 있다. 바꾸지 말 것.
- 실제 크리덴셜 스터핑용 유출 계정 목록 수집·사용 금지.

## 구성

```
API대입공격_실습/
├─ app/
│  ├─ main.py      FastAPI 조회 API (vuln/safe 모드 전환)
│  ├─ data.py      합성 고객·대출모집인 데이터
│  └─ logbus.py    조회 로그 버스(JSONL + 메모리 버퍼)
├─ detect/
│  └─ scorer.py    이상행위 점수화(룰 기반)
├─ attack/
│  └─ replay.py    대입 조회 공격 재현(랩 전용)
├─ tests/
│  └─ test_scorer.py
├─ run_experiment.py   A~D 비교 실험 자동 러너
└─ requirements.txt
```

## 설치

```bash
cd 런북/API대입공격_실습
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 1. 취약 모드로 사고 재현

터미널 1 — 취약 서버(인가 검증 없음):
```bash
LAB_MODE=vuln python -m uvicorn app.main:app --port 8000
# Windows PowerShell:  $env:LAB_MODE="vuln"; python -m uvicorn app.main:app --port 8000
```

터미널 2 — 대입 조회 공격:
```bash
python -m attack.replay
```

기대 결과: broker01은 원래 고객 1~50번만 담당하지만, **1~500번을 전부 조회 성공**.
→ 51~500번(남의 고객 **450건**)이 유출된다. **이것이 IDOR(BOLA) 침해.**

## 2. 안전 모드로 방어

```bash
LAB_MODE=safe python -m uvicorn app.main:app --port 8000
python -m attack.replay
```

기대 결과: 1~50번(담당 고객)만 200, 51~500번은 **403(담당 아님)**.
→ 비인가 유출 **0건**. 서버가 "이 모집인이 이 고객을 볼 권한이 있는가"를 재검증(객체 인가).

## 3. 실시간 탐지 차단

취약 모드라도 탐지를 켜면(`LAB_DETECT=1`), 점수가 임계치를 넘는 순간 429로 차단된다.
```bash
LAB_MODE=vuln LAB_DETECT=1 python -m uvicorn app.main:app --port 8000
python -m attack.replay   # 수십 건 조회 후 차단됨
```

## 4. 비교 실험 (발표 하이라이트)

서버를 따로 띄울 필요 없이 러너가 A~D 구성을 자동으로 실험한다.
```bash
python run_experiment.py
```

실측 예시(이 랩 기준):

| 구성 | 비인가 유출 | 차단 시점 | 의미 |
|---|---|---|---|
| A) 취약 + 탐지없음 | **450건** | 차단없음 | 만점 평가여도 전량 유출 |
| B) 취약 + 실시간탐지 | **0건** | 51번째 요청 | 점수화로 조기 차단 |
| C) 안전(인가+잠금) | **0건** | — | 설계 단계 예방 |
| D) 안전 + 탐지 | **0건** | 51번째 요청 | 예방+탐지 |

> 핵심 메시지: **A**는 "보안 상시평가 만점(서류)"만 있는 상태 = 신한 사고.
> **B**는 월 1회 점검을 실시간 점수화로 바꾼 것. **C/D**는 설계 단계에서 막은 것.
> → **컴플라이언스(만점) ≠ 실제 보안.**

## 5. 테스트

```bash
python -m pytest -q
```

## 코드가 보여주는 '진짜 취약점'

`app/main.py`의 `lookup()` 안, 단 한 블록이 사고의 핵심이다.

```python
# vuln 모드: 로그인만 됐으면 아무 고객이나 조회 (← IDOR/BOLA)
# safe 모드:
if MODE == "safe":
    owned = data.BROKERS[broker_id]["owned_customers"]
    if customer_id not in owned:
        raise HTTPException(status_code=403, detail="담당 고객이 아닙니다")
```

로그인(인증)은 둘 다 통과한다. 차이는 **"이 자원을 볼 자격이 있는가"를 서버가 다시 보는가**다.
정상 로그인 상태에서 값(customer_id)만 바꾼 요청이라, 네트워크 레벨에선 평범해 보인다.
→ 그래서 IPS 시그니처로는 못 잡고, **애플리케이션 인가 + 행위 기반 탐지(UEBA)**가 필요하다.
(제안서 03의 IPS 한계와 대비되는 지점.)

## 확장 아이디어

- `detect/`에 scikit-learn **Isolation Forest**를 추가해 "느린 대입"도 탐지(룰 보완).
- 로그를 Elastic/Grafana로 보내 대시보드화.
- step-up 인증(추가 OTP 요구) 분기를 429 대신 구현.
