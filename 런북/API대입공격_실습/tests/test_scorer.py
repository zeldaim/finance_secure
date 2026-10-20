"""scorer 단위 테스트 — 기대값은 테스트에서 독립적으로 계산(하드코딩).

실행: python -m pytest -q   (실습 루트에서)
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detect import scorer   # noqa: E402


def _lookup(cid, broker="broker01", ip="9.9.9.9", ok=True):
    return {"action": "lookup", "broker": broker, "ip": ip,
            "customer_id": cid, "ok": ok, "ts": time.time()}


def test_normal_user_is_low_score():
    # 사람이 자기 고객 몇 명만 조회 → normal
    events = [_lookup(c) for c in (3, 7, 12)]
    out = scorer.assess(events)
    assert out["verdict"] == "normal"
    assert out["score"] < scorer.T_ALERT


def test_sequential_mass_lookup_is_blocked():
    # 1..60 순차 대입 조회 → 과다 + 고유다수 + 순차 → block
    events = [_lookup(c) for c in range(1, 61)]
    out = scorer.assess(events)
    assert out["verdict"] == "block"
    assert out["score"] >= scorer.T_BLOCK


def test_sequential_ratio_detects_increment():
    assert scorer._sequential_ratio([1, 2, 3, 4]) == 1.0
    assert scorer._sequential_ratio([10, 20, 30]) == 0.0
    assert scorer._sequential_ratio([5]) == 0.0


def test_login_fail_then_success_adds_weight():
    base = [_lookup(c) for c in (1, 2)]
    cred = base + [
        {"action": "login", "broker": "broker01", "ip": "9.9.9.9",
         "ok": False, "ts": time.time()},
        {"action": "login", "broker": "broker01", "ip": "9.9.9.9",
         "ok": True, "ts": time.time()},
    ]
    assert scorer.assess(cred)["score"] > scorer.assess(base)["score"]
