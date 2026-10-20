"""합성(가짜) 고객 데이터 생성 — 실제 개인정보 아님.

이번 신한은행 사고에서 유출된 항목(고객명/전화번호/연소득/산출한도/주민번호/CI)을
'형태만' 모사한 더미 데이터다. 주민번호/CI는 명백히 가짜 패턴을 쓴다.
"""
from __future__ import annotations

import random

# 재현 가능하도록 시드 고정 (교육용)
_RNG = random.Random(20261020)

_SURNAMES = ["김", "이", "박", "최", "정", "강", "조", "윤", "장", "임"]
_GIVEN = ["민준", "서연", "도윤", "하은", "지후", "수아", "예준", "지유", "주원", "서윤"]


def _fake_customer(cid: int) -> dict:
    name = _RNG.choice(_SURNAMES) + _RNG.choice(_GIVEN)
    # 전화번호/주민번호/CI 모두 '가짜'임이 드러나는 패턴 사용
    phone = f"010-0000-{cid % 10000:04d}"
    rrn = f"000000-0{cid % 1000000:06d}"          # 실제 주민번호 규칙 아님(가짜)
    ci = f"CI-TEST-{cid:08d}"                      # 실제 CI 아님(가짜)
    income = 2000 + (cid * 37) % 9000              # 연소득(만원)
    limit = income * 3                             # 산출한도(만원)
    return {
        "customer_id": cid,
        "name": name,
        "phone": phone,
        "rrn": rrn,
        "ci": ci,
        "annual_income": income,
        "loan_limit": limit,
    }


# 고객 1..N (순차 ID = 자동 대입에 취약한 구조를 일부러 재현)
CUSTOMERS: dict[int, dict] = {cid: _fake_customer(cid) for cid in range(1, 5001)}


# 대출모집인(broker) 계정. 각 모집인은 '자기 고객'만 볼 권한이 있다.
# 안전 모드에서는 이 소유권을 서버가 검증한다.
BROKERS: dict[str, dict] = {
    "broker01": {
        "password": "lab-demo-pw-01",            # 랩 전용 더미 비밀번호
        "owned_customers": list(range(1, 51)),   # 1~50번 고객만 담당
    },
    "broker02": {
        "password": "lab-demo-pw-02",
        "owned_customers": list(range(51, 101)),
    },
}
