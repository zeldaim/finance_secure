"""조회 로그 버스 — 모든 조회 요청을 구조화(JSON) 이벤트로 기록한다.

탐지 엔진(detect/)은 이 로그를 읽어 이상행위 점수를 계산한다.
실제 환경의 '접근 로그 → SIEM/UEBA' 파이프라인을 축소 재현한 것.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent.parent / "access_log.jsonl"

# 실시간 탐지가 읽어가는 메모리 링버퍼(최근 이벤트)
_RECENT: deque[dict] = deque(maxlen=5000)
_LOCK = threading.Lock()


def emit(event: dict) -> None:
    """조회 이벤트 1건 기록 (파일 append + 메모리 버퍼)."""
    event.setdefault("ts", time.time())
    with _LOCK:
        _RECENT.append(event)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def recent(window_sec: float = 60.0) -> list[dict]:
    """최근 window_sec 초 이내 이벤트 목록."""
    cutoff = time.time() - window_sec
    with _LOCK:
        return [e for e in _RECENT if e.get("ts", 0) >= cutoff]


def reset() -> None:
    """실험 반복용: 로그 초기화."""
    with _LOCK:
        _RECENT.clear()
        if LOG_PATH.exists():
            LOG_PATH.unlink()
