#!/usr/bin/env python3
"""
test_maildet.py - maildet 탐지 엔진 회귀 테스트
실행: python test_maildet.py   (종료코드 0=전체통과)

각 샘플의 기대 조치/핵심 탐지코드를 단언한다. 룰 수정 시 회귀 방지.
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import maildet

HERE = os.path.dirname(os.path.abspath(__file__))
SDIR = os.path.join(os.path.dirname(HERE), "samples")
POL = json.load(open(os.path.join(SDIR, "spf_policy.json"), encoding="utf-8"))

# (파일, 기대 action, 반드시 포함돼야 할 findings, 포함되면 안 되는 findings)
CASES = [
    ("01_legit.eml",          "pass",       [],                              ["dmarc_fail", "eicar"]),
    ("02_spoof_dmarc_fail.eml","quarantine", ["dmarc_fail", "display_name_spoof"], ["eicar"]),
    ("03_phish_lookalike.eml","reject",      ["urgency", "credential_lure", "url_text_mismatch", "shortener_url"], []),
    ("04_html_smuggling.eml", "quarantine",  ["html_smuggling"],              ["eicar"]),
    ("05_eicar_attach.eml",   "reject",      ["eicar", "double_extension", "dangerous_attach"], []),
]

def run():
    passed = failed = 0
    for fname, exp_action, must, mustnot in CASES:
        r = maildet.analyze(os.path.join(SDIR, fname), POL)
        codes = {f["code"] for f in r["findings"]}
        errs = []
        if r["action"] != exp_action:
            errs.append(f"action={r['action']} (기대 {exp_action})")
        for m in must:
            if m not in codes:
                errs.append(f"'{m}' 미탐(누락)")
        for n in mustnot:
            if n in codes:
                errs.append(f"'{n}' 오탐(발생)")
        # 중복 집계 회귀 방지: 같은 code+detail 중복 없어야
        seen = set(); dup = False
        for f in r["findings"]:
            k = (f["code"], f["detail"])
            if k in seen: dup = True
            seen.add(k)
        if dup:
            errs.append("findings 중복 집계")
        if errs:
            failed += 1
            print(f"FAIL  {fname}: " + "; ".join(errs))
        else:
            passed += 1
            print(f"PASS  {fname}  -> {r['action']} (score={r['score']})")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(run())
