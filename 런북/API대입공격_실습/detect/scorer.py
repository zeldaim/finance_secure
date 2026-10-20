"""이상행위 점수화(risk scorer) — 룰 기반.

한 (broker 계정, source_ip) 주체가 최근 윈도 안에서 보인 조회 행동을
신호별 가중합으로 점수화한다. 임계치를 넘으면 차단 신호를 낸다.

이번 신한 사고의 핵심 징후를 신호로 옮긴 것:
  - 짧은 시간에 과다 조회           → 사람이 수동으로 불가
  - 서로 다른 고객을 다수 조회       → IDOR(남의 데이터 열람) 징후
  - 고객번호가 순차적              → 자동 대입의 전형
  - 로그인 실패 뒤 성공            → 크리덴셜 스터핑/대입 징후
"""
from __future__ import annotations

from dataclasses import dataclass, field

# 단계 임계치
T_ALERT = 50     # 이 이상이면 경보 + step-up
T_BLOCK = 80     # 이 이상이면 차단

# 신호 가중치
W_VOLUME = 6          # 과다 조회 (건수 구간당)
W_UNIQUE = 7          # 고유 고객 수 (건수 구간당)
W_SEQUENTIAL = 25     # 순차 조회 패턴
W_LOGIN_FAIL = 20     # 로그인 실패 뒤 성공
W_OFF_HOURS = 10      # 비업무 시간대


@dataclass
class Signals:
    lookups: int = 0
    unique_customers: int = 0
    sequential_ratio: float = 0.0
    login_fail_then_success: bool = False
    off_hours: bool = False
    detail: dict = field(default_factory=dict)


def _sequential_ratio(ids: list[int]) -> float:
    """연속 증가(…,n,n+1,…) 비율. 자동 대입일수록 1.0에 가깝다."""
    if len(ids) < 2:
        return 0.0
    steps = [b - a for a, b in zip(ids, ids[1:])]
    inc = sum(1 for s in steps if s == 1)
    return inc / len(steps)


def extract_signals(events: list[dict], off_hours: bool = False) -> Signals:
    """한 주체(이미 필터링된 이벤트 목록)의 신호를 추출."""
    lookups = [e for e in events if e.get("action") == "lookup"]
    ids = [e["customer_id"] for e in lookups if "customer_id" in e]
    unique = sorted(set(ids))

    logins = [e for e in events if e.get("action") == "login"]
    had_fail = any(not e.get("ok", True) for e in logins)
    had_success = any(e.get("ok", False) for e in logins)

    return Signals(
        lookups=len(lookups),
        unique_customers=len(unique),
        sequential_ratio=_sequential_ratio(ids),
        login_fail_then_success=had_fail and had_success,
        off_hours=off_hours,
        detail={"unique_ids_sample": unique[:10]},
    )


def score(sig: Signals) -> int:
    """신호 → 위험 점수(0~100+)."""
    s = 0
    # 10건 구간마다 가중 (과다 조회)
    s += min(sig.lookups // 10, 6) * W_VOLUME
    s += min(sig.unique_customers // 10, 6) * W_UNIQUE
    if sig.sequential_ratio >= 0.8 and sig.unique_customers >= 5:
        s += W_SEQUENTIAL
    if sig.login_fail_then_success:
        s += W_LOGIN_FAIL
    if sig.off_hours:
        s += W_OFF_HOURS
    return s


def verdict(points: int) -> str:
    """점수 → 판정(normal/alert/block)."""
    if points >= T_BLOCK:
        return "block"
    if points >= T_ALERT:
        return "alert"
    return "normal"


def assess(events: list[dict], off_hours: bool = False) -> dict:
    """이벤트 목록 → {점수, 판정, 신호}."""
    sig = extract_signals(events, off_hours=off_hours)
    pts = score(sig)
    return {
        "score": pts,
        "verdict": verdict(pts),
        "signals": sig.__dict__,
    }
