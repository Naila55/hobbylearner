from typing import Optional, Dict, Tuple
import re, spf, dkim, dns.resolver

dns.resolver.default_resolver = dns.resolver.Resolver()
dns.resolver.default_resolver.nameservers = ['8.8.8.8']

def _field(header: str, name: str) -> Optional[str]:
    m = re.search(rf"^{name}:[ \t]*(.+)$", header, re.I | re.M)
    return m.group(1).strip() if m else None

def _extract_header(raw: bytes) -> str:
    return raw.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")

def _sending_ip(header: str) -> Optional[str]:
    ips = re.findall(r"Received: from .*?\[(\d{1,3}(?:\.\d{1,3}){3})\]", header)
    return ips[-1] if ips else None

def _helo_domain(header: str) -> Optional[str]:
    m = re.search(r"Received: from (\S+)", header)
    return m.group(1) if m else None

def _from_domain(header: str) -> Optional[str]:
    fr = _field(header, "From")
    return fr.split("@")[1].split(">")[0].lower() if fr and "@" in fr else None

def _mail_from_domain(header: str) -> Optional[str]:
    rp = _field(header, "Return-Path")
    if rp and "@" in rp:
        return rp.strip("<>").split("@")[1].lower()
    return _from_domain(header)

def _dkim_domain(raw: bytes) -> Optional[str]:
    headers = _extract_header(raw)
    unfolded = re.sub(r"\r\n\s+", " ", headers)
    m = re.search(r"DKIM-Signature:.*\bd=([^;\s]+)", unfolded, re.I)
    return m.group(1).lower() if m else None

def _dkim_unfolded(raw: bytes) -> str:
    try:
        d = dkim.DKIM(raw)
        result = d.verify()
        return "pass" if result else "fail"
    except Exception as e:
        print(" DKIM error:", e)
        return "fail"

def _spf(ip: str, sender: str, helo: str) -> str:
    try:
        res, *_ = spf.check2(i=ip, s=sender, h=helo)
        return res
    except Exception as e:
        print(" SPF error:", e)
        return "fail"

def _dmarc(domain: str, spf_ok: bool, dkim_ok: bool) -> str:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode()
            if txt.lower().startswith("v=dmarc1"):
                return "pass" if (spf_ok or dkim_ok) else "fail"
        return "fail"
    except Exception as e:
        print(" DMARC error:", e)
        return "fail"

def analyze_email(raw: bytes) -> Tuple[str, Dict[str, str], str, str, str]:
    try:
        print("RAW EMAIL PREVIEW ")
        preview = raw[:2000].decode("utf-8", errors="replace")
        print(preview)
    except Exception as e:
        print(" Preview error:", e)

    hdr = _extract_header(raw)
    ip = _sending_ip(hdr) or "0.0.0.0"
    helo = _helo_domain(hdr) or "localhost"
    from_dom = _from_domain(hdr) or "example.com"
    mfrom_dom = _mail_from_domain(hdr) or from_dom
    dkim_dom = _dkim_domain(raw)

    spf_res = _spf(ip, mfrom_dom, helo)
    dkim_res = _dkim_unfolded(raw)

    spf_ok = spf_res in ("pass", "softpass") and mfrom_dom.endswith(from_dom)
    dkim_ok = dkim_res == "pass" or (dkim_dom and dkim_dom.endswith(from_dom))

    if dkim_res != "pass" and dkim_ok:
        print(f" DKIM verified by domain match: {dkim_dom} ≈ {from_dom}")
        dkim_res = "domain match"

    dmarc_res = _dmarc(from_dom, spf_ok, dkim_ok)

    verdict = (
        "Genuine" if dmarc_res == "pass"
        else "Likely Spoofed" if spf_res == "fail" and dkim_res == "fail"
        else "Possibly Genuine but Suspicious"
    )

    auth = {"SPF": spf_res, "DKIM": dkim_res, "DMARC": dmarc_res}
    return verdict, auth, _field(hdr, "From") or "—", _field(hdr, "Reply-To") or "—", _field(hdr, "Return-Path") or "—"
