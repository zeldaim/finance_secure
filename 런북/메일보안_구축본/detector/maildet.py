#!/usr/bin/env python3
"""
maildet.py - 금융권 피싱/악성 메일 탐지 엔진 (순수 표준 라이브러리)

용도: 수신한 .eml 파일을 분석해 피싱/사칭/악성 첨부를 점수화하고 조치를 판정한다.
      메일서버(Postfix+Rspamd) 앞단 또는 격리 폴더 사후분석용 PoC.
의존성: 없음 (Python 3.8+ 표준 라이브러리만). 격리 랩/교육용.

실행:  python maildet.py <메일.eml> [--spf-policy policy.json] [--json]
       python maildet.py --selftest     # 내장 샘플로 자체 검증

조치 임계값(기본): score >= 15 reject / >= 6 quarantine / else pass
"""
import sys, os, re, json, base64, email, email.policy
from email.utils import parseaddr, getaddresses

# ---- 설정: 가중치/사전 (운영 시 외부 파일로 분리 가능) ----
WEIGHTS = {
    "dmarc_fail": 8,          # From 도메인 정렬 실패 + SPF fail
    "display_name_spoof": 6,  # 표시이름은 기관 사칭, 도메인은 다름
    "lookalike_domain": 5,    # 유사 도메인(oO/rn 등)
    "url_text_mismatch": 5,   # 링크 텍스트와 실제 href 도메인 불일치
    "ip_literal_url": 4,      # http://1.2.3.4/... 형태
    "punycode_url": 4,        # xn-- 퓨니코드
    "shortener_url": 3,       # 단축 URL
    "urgency": 3,             # 긴급성 유도 문구
    "credential_lure": 4,     # 인증/비밀번호/계정 유도
    "dangerous_attach": 6,    # 실행형 첨부(.exe/.js/.hta ...)
    "double_extension": 5,    # 이중 확장자 (invoice.pdf.exe)
    "html_smuggling": 7,      # HTML smuggling 패턴
    "eicar": 10,              # EICAR 테스트 파일(악성 모사)
}
INSTITUTIONS = ["서울보증", "sgi", "국민카드", "롯데카드", "농협", "nh", "보험", "건강검진",
                "insurance", "bank", "card", "증권", "금융"]
URGENCY = ["긴급", "즉시", "오늘", "마감", "지금", "확인 바", "미확인", "정지", "차단",
           "urgent", "immediately", "now", "verify", "suspend", "expire"]
CREDENTIAL = ["비밀번호", "인증", "로그인", "계정", "본인확인", "otp", "password",
              "credential", "login", "sign in", "verify your account"]
DANGEROUS_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".bat",
                 ".cmd", ".ps1", ".jar", ".lnk", ".wsf", ".msi"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "han.gl"}
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def domain_of(addr):
    _, a = parseaddr(addr)
    return a.split("@")[-1].lower() if "@" in a else ""


def is_lookalike(dom):
    # 혼동 문자/과도한 하이픈/숫자치환 간이 탐지
    if re.search(r"(rn|vv|0[a-z]|[a-z]0|l1|1l)", dom):
        if any(b in dom for b in ["bank", "card", "sgi", "nh", "pay", "secure", "login"]):
            return True
    if dom.count("-") >= 3:
        return True
    return False


def extract_urls(html_or_text):
    # (anchor_text, href) 쌍과 평문 URL 모두 수집
    pairs = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                       html_or_text, re.I | re.S)
    plain = re.findall(r'https?://[^\s"\'<>]+', html_or_text)
    return pairs, plain


def analyze(eml_path, spf_policy=None):
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    findings = []  # (코드, 설명)
    def hit(code, detail=""):
        findings.append((code, detail))

    # ---- 헤더: From / Return-Path / SPF 정합성 ----
    from_hdr = str(msg.get("From", ""))
    from_dom = domain_of(from_hdr)
    disp_name = parseaddr(from_hdr)[0]
    return_path = domain_of(str(msg.get("Return-Path", "")) or
                            str(msg.get("Sender", "")))
    received_spf = str(msg.get("Received-SPF", "")).lower()

    # SPF 판정: Received-SPF 헤더 우선, 없으면 정책(IP->도메인) 조회
    spf_result = "unknown"
    if "pass" in received_spf:
        spf_result = "pass"
    elif "fail" in received_spf or "softfail" in received_spf:
        spf_result = "fail"
    elif spf_policy:
        # 간이: 보낸 서버 IP가 해당 도메인 허용 목록에 있는가
        src_ip = None
        m = re.search(r'client-ip=([0-9.]+)', received_spf)
        if m:
            src_ip = m.group(1)
        allowed = spf_policy.get(from_dom, [])
        spf_result = "pass" if (src_ip and src_ip in allowed) else "fail"

    # DMARC 정합성(간이): From 도메인 vs Return-Path 도메인 정렬 + SPF
    aligned = bool(return_path) and (return_path == from_dom or
                                     return_path.endswith("." + from_dom))
    if spf_result == "fail" or (return_path and not aligned):
        hit("dmarc_fail", f"From={from_dom} ReturnPath={return_path} spf={spf_result}")

    # 표시이름 사칭: 이름엔 기관, 도메인은 무관
    if disp_name and any(k in disp_name.lower() for k in INSTITUTIONS):
        if from_dom and not any(k in from_dom for k in INSTITUTIONS):
            hit("display_name_spoof", f"name='{disp_name}' dom={from_dom}")

    if from_dom and is_lookalike(from_dom):
        hit("lookalike_domain", from_dom)

    # ---- 본문 수집(평문+HTML) ----
    subject = str(msg.get("Subject", ""))
    body_text, body_html = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_filename():
            continue
        if ctype == "text/plain":
            body_text += part.get_content()
        elif ctype == "text/html":
            body_html += part.get_content()
    corpus = f"{subject}\n{body_text}\n{body_html}"

    low = corpus.lower()
    if any(u.lower() in low for u in URGENCY):
        hit("urgency", next(u for u in URGENCY if u.lower() in low))
    if any(c.lower() in low for c in CREDENTIAL):
        hit("credential_lure", next(c for c in CREDENTIAL if c.lower() in low))

    # ---- URL 분석 ----
    pairs, plain = extract_urls(body_html or body_text)
    for href, text in pairs:
        href_dom = re.sub(r'^https?://', '', href).split('/')[0].lower()
        text_dom = re.sub(r'^https?://', '', re.sub(r'<[^>]+>', '', text)).split('/')[0].lower()
        if text_dom and ('.' in text_dom) and href_dom and text_dom not in href_dom:
            hit("url_text_mismatch", f"text={text_dom} -> href={href_dom}")
    seen_hosts = set()  # 같은 호스트 중복 집계 방지
    for url in plain + [h for h, _ in pairs]:
        host = re.sub(r'^https?://', '', url).split('/')[0].lower()
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}', host):
            hit("ip_literal_url", host)
        if host.startswith("xn--") or ".xn--" in host:
            hit("punycode_url", host)
        if host in SHORTENERS:
            hit("shortener_url", host)

    # ---- 첨부 분석 ----
    for part in msg.walk():
        fn = part.get_filename()
        if not fn:
            continue
        name = fn.lower()
        ext = os.path.splitext(name)[1]
        if ext in DANGEROUS_EXT:
            hit("dangerous_attach", fn)
        # 이중 확장자: 중간에 문서형 확장자 + 끝에 실행형
        if re.search(r'\.(pdf|docx?|xlsx?|hwp|jpg|png)\.(exe|scr|js|hta|bat|vbs)$', name):
            hit("double_extension", fn)
        # 내용 검사
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        text = payload.decode("utf-8", "ignore")
        if EICAR in text:
            hit("eicar", fn)
        if ext in {".html", ".htm"}:
            has_blob = ("msSaveOrOpenBlob" in text or "new Blob" in text or
                        "application/octet-stream" in text)
            has_b64 = re.search(r'atob\(["\'][A-Za-z0-9+/=]{120,}', text) is not None
            if has_blob and has_b64:
                hit("html_smuggling", fn)

    # ---- 점수/판정 ----
    score = sum(WEIGHTS.get(code, 0) for code, _ in findings)
    if score >= 15:
        action = "reject"
    elif score >= 6:
        action = "quarantine"
    else:
        action = "pass"

    return {
        "file": os.path.basename(eml_path),
        "from": from_hdr, "subject": subject,
        "spf": spf_result, "score": score, "action": action,
        "findings": [{"code": c, "weight": WEIGHTS.get(c, 0), "detail": d}
                     for c, d in findings],
    }


def print_report(r):
    icon = {"reject": "[X]", "quarantine": "[!]", "pass": "[ok]"}[r["action"]]
    print(f"\n{icon} [{r['action'].upper()}] score={r['score']}  {r['file']}")
    print(f"   From: {r['from']}")
    print(f"   Subj: {r['subject']}   (SPF={r['spf']})")
    if r["findings"]:
        for f in r["findings"]:
            print(f"   - +{f['weight']:<2} {f['code']:<20} {f['detail']}")
    else:
        print("   - (no findings)")


if __name__ == "__main__":
    args = sys.argv[1:]
    policy = None
    if "--spf-policy" in args:
        i = args.index("--spf-policy")
        policy = json.load(open(args[i + 1], encoding="utf-8"))
        del args[i:i + 2]
    as_json = "--json" in args
    if as_json:
        args.remove("--json")

    if not args or args[0] == "--selftest":
        here = os.path.dirname(os.path.abspath(__file__))
        sdir = os.path.join(os.path.dirname(here), "samples")
        files = sorted(f for f in os.listdir(sdir) if f.endswith(".eml"))
        pol = None
        pf = os.path.join(sdir, "spf_policy.json")
        if os.path.exists(pf):
            pol = json.load(open(pf, encoding="utf-8"))
        results = [analyze(os.path.join(sdir, f), pol) for f in files]
        for r in results:
            print_report(r)
        print("\n=== 요약 ===")
        for r in results:
            print(f"  {r['action']:<10} score={r['score']:<3} {r['file']}")
        sys.exit(0)

    r = analyze(args[0], policy)
    print(json.dumps(r, ensure_ascii=False, indent=2) if as_json else None)
    if not as_json:
        print_report(r)
