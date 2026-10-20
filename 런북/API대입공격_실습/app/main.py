"""취약/안전 모드를 전환할 수 있는 '대출모집인 조회 API' (교육용 랩).

실행:
    # 취약 모드 (인가 검증 없음 + 억제 없음)  ← 사고 재현용
    LAB_MODE=vuln python -m uvicorn app.main:app --port 8000

    # 안전 모드 (객체 인가 + 레이트리밋 + 실시간 탐지 차단)
    LAB_MODE=safe python -m uvicorn app.main:app --port 8000

환경변수:
    LAB_MODE   vuln | safe   (기본 vuln)
    LAB_DETECT 1 | 0         실시간 탐지 on/off (기본: safe면 1, vuln이면 0)

주의: 반드시 로컬(127.0.0.1)에서만. 합성 데이터만 사용.
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request

# detect/ 를 import 경로에 추가
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import data, logbus              # noqa: E402
from detect import scorer                 # noqa: E402

MODE = os.environ.get("LAB_MODE", "vuln").lower()
DETECT = os.environ.get("LAB_DETECT", "1" if MODE == "safe" else "0") == "1"

app = FastAPI(title=f"대출모집인 조회 API (lab, mode={MODE})")

# 간이 세션/상태 (교육용 인메모리)
_SESSIONS: dict[str, str] = {}          # token -> broker_id
_LOGIN_FAILS: dict[str, int] = {}       # broker_id -> 연속 실패 수
_BLOCKED: set[str] = set()              # 차단된 주체 키 (broker_id|ip)
MAX_LOGIN_FAILS = 5                     # 안전 모드 계정 잠금 임계


def _subject_key(broker_id: str, request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{broker_id}|{ip}"


def _run_detection(broker_id: str, request: Request) -> None:
    """실시간 탐지: 이 주체의 최근 행동을 점수화하고, block이면 차단목록에 추가."""
    if not DETECT:
        return
    key = _subject_key(broker_id, request)
    ip = request.client.host if request.client else "unknown"
    events = [e for e in logbus.recent(60.0)
              if e.get("broker") == broker_id and e.get("ip") == ip]
    result = scorer.assess(events)
    if result["verdict"] == "block":
        _BLOCKED.add(key)


def require_session(authorization: str = Header(default="")) -> str:
    """Bearer 토큰 → broker_id. 인증(authentication) 단계."""
    token = authorization.removeprefix("Bearer ").strip()
    broker_id = _SESSIONS.get(token)
    if not broker_id:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다")
    return broker_id


@app.post("/login")
def login(payload: dict, request: Request):
    broker_id = str(payload.get("broker_id", ""))
    password = str(payload.get("password", ""))
    ip = request.client.host if request.client else "unknown"
    broker = data.BROKERS.get(broker_id)

    # 안전 모드: 계정 잠금 (대입/크리덴셜 스터핑 억제)
    if MODE == "safe" and _LOGIN_FAILS.get(broker_id, 0) >= MAX_LOGIN_FAILS:
        logbus.emit({"action": "login", "broker": broker_id, "ip": ip,
                     "ok": False, "reason": "locked"})
        raise HTTPException(status_code=429, detail="계정 잠금: 로그인 시도 초과")

    ok = bool(broker and broker["password"] == password)
    logbus.emit({"action": "login", "broker": broker_id, "ip": ip, "ok": ok})

    if not ok:
        _LOGIN_FAILS[broker_id] = _LOGIN_FAILS.get(broker_id, 0) + 1
        raise HTTPException(status_code=401, detail="인증 실패")

    _LOGIN_FAILS[broker_id] = 0
    token = uuid.uuid4().hex
    _SESSIONS[token] = broker_id
    return {"token": token}


@app.get("/loan/lookup/{customer_id}")
def lookup(customer_id: int, request: Request,
           broker_id: str = Depends(require_session)):
    """대출 심사 현황 조회.

    vuln 모드: 로그인만 됐으면 '아무 고객'이나 조회 가능 (IDOR/BOLA).
    safe 모드: 이 모집인이 '담당하는 고객'인지 서버가 재검증 (객체 인가).
    """
    ip = request.client.host if request.client else "unknown"
    key = _subject_key(broker_id, request)

    # 실시간 탐지로 이미 차단된 주체
    if DETECT and key in _BLOCKED:
        logbus.emit({"action": "lookup", "broker": broker_id, "ip": ip,
                     "customer_id": customer_id, "ok": False, "reason": "blocked"})
        raise HTTPException(status_code=429, detail="이상행위 탐지로 차단되었습니다")

    customer = data.CUSTOMERS.get(customer_id)
    if not customer:
        logbus.emit({"action": "lookup", "broker": broker_id, "ip": ip,
                     "customer_id": customer_id, "ok": False, "reason": "notfound"})
        raise HTTPException(status_code=404, detail="해당 고객 없음")

    # ★ 핵심 차이: 객체 단위 인가(Object-Level Authorization)
    if MODE == "safe":
        owned = data.BROKERS[broker_id]["owned_customers"]
        if customer_id not in owned:
            logbus.emit({"action": "lookup", "broker": broker_id, "ip": ip,
                         "customer_id": customer_id, "ok": False,
                         "reason": "forbidden"})
            _run_detection(broker_id, request)
            raise HTTPException(status_code=403, detail="담당 고객이 아닙니다")

    # 조회 성공 → 로그 기록 후 탐지 평가
    logbus.emit({"action": "lookup", "broker": broker_id, "ip": ip,
                 "customer_id": customer_id, "ok": True})
    _run_detection(broker_id, request)
    return customer


@app.get("/healthz")
def healthz():
    return {"mode": MODE, "detect": DETECT, "ts": time.time()}
