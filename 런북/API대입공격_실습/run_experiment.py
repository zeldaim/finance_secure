"""비교 실험 러너 — 같은 공격을 4개 구성(A~D)에 흘려 결과를 표로 출력.

각 구성마다 uvicorn 서버를 환경변수를 바꿔 띄우고, attack/replay.py를 실행한다.
서버는 자식 프로세스로 띄웠다 내린다.

실행: python run_experiment.py   (실습 루트에서)
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from attack import replay   # noqa: E402

PORT = 8000
BASE = f"http://127.0.0.1:{PORT}"

# (라벨, LAB_MODE, LAB_DETECT)
CONFIGS = [
    ("A) 취약+탐지없음",  "vuln", "0"),
    ("B) 취약+실시간탐지", "vuln", "1"),
    ("C) 안전(인가+잠금)", "safe", "0"),
    ("D) 안전+탐지",      "safe", "1"),
]


def _wait_ready(timeout=15.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if httpx.get(f"{BASE}/healthz", timeout=1.0).status_code == 200:
                return True
        except Exception:
            time.sleep(0.3)
    return False


def _start_server(mode: str, detect: str) -> subprocess.Popen:
    env = dict(os.environ, LAB_MODE=mode, LAB_DETECT=detect)
    # 매 구성마다 로그 초기화
    log = ROOT / "access_log.jsonl"
    if log.exists():
        log.unlink()
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--port", str(PORT), "--log-level", "warning"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def main() -> None:
    rows = []
    for label, mode, detect in CONFIGS:
        proc = _start_server(mode, detect)
        try:
            if not _wait_ready():
                rows.append((label, "서버 기동 실패", "", ""))
                continue
            # broker01은 1~50만 담당. 1~500을 순차 대입 → 51+는 남의 데이터.
            res = replay.run(start=1, count=500, owned_ids=set(range(1, 51)))
            rows.append((
                label,
                res.get("unauthorized_count", "-"),
                res.get("blocked_at_request") or "차단없음",
                f"{res.get('elapsed_sec', '-')}s",
            ))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            time.sleep(0.5)

    # 결과 표
    print("\n" + "=" * 64)
    print(f"{'구성':<20}{'비인가유출':>10}{'차단시점(req)':>16}{'소요':>10}")
    print("-" * 64)
    for label, stolen, blocked, elapsed in rows:
        print(f"{label:<20}{str(stolen):>10}{str(blocked):>16}{elapsed:>10}")
    print("=" * 64)
    print("해석: A=만점 평가여도 전량 유출 / B=실시간 점수화로 조기 차단 /")
    print("      C·D=설계 단계 인가 검증이 공격 성립 자체를 차단")


if __name__ == "__main__":
    main()
