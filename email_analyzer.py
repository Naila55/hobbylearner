"""
Analyse a raw `.eml` file and return:
    verdict               (str)
    auth                  (dict: {"SPF":..,"DKIM":..,"DMARC":..})
    from_header           (str)
    reply_to_header       (str)
Works on Python 3.9+
"""

from typing import Optional, Dict, Tuple
import re, spf, dkim, dns. resolver, dmarc


def _field(header: str, name: str) -> Optional[str]:
    m = re.search(rf"^{name}:\s*(.+)$", header, re.I | re.M)
    return m.group(1).strip() if m else None


def _extract_header(raw: bytes) -> str:
    return raw.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")


def _sending_ip(header: str) -> Optional[str]:
    m = re.findall(r"Received: from .* \[(\d+\.\d+\.\d+\.\d+)\]", header)
    return m[-1] if m else None


def _helo_domain(header: str) -> Optional[str]:
    m = re.search(r"Received: from (\S+)", header)
    return m.group(1) if m else None


def _from_domain(header: str) -> Optional[str]:
    fr = _field(header, "From")
    return fr.split("@")[-1].split(">")[0].lower() if fr and "@" in fr else None


def _mail_from_domain(header: str) -> Optional[str]:
    rp = _field(header, "Return-Path")
    if rp and "@" in rp:
        return rp.strip("<>").split("@")[1].lower()
    return _from_domain(header)


def _dkim_domain(raw: bytes) -> Optional[str]:
    m = re.search(rb"DKIM-Signature:.*\sd=([^;\s]+)", raw, re.I)
    return m.group(1).decode() if m else None



def _spf(ip: str, sender: str, helo: str) -> str:
    try:
        res, *_ = spf.check2(i=ip, s=sender, h=helo)
        return res
    except Exception:
        return "fail"


def _dkim(raw: bytes) -> str:
    try:
        return "pass" if dkim.verify(raw) else "fail"
    except Exception:
        return "fail"


def _dmarc(org_dom: str, spf_ok: bool, dkim_ok: bool) -> str:
    try:
        rec = dmarc.get_record(org_dom)
        if not rec:
            return "fail"
        return "pass" if (spf_ok or dkim_ok) else "fail"
    except Exception:
        return "fail"

def analyze_email(raw: bytes) -> Tuple[str, Dict[str, str], str, str]:
    hdr = _extract_header(raw)

    ip        = _sending_ip(hdr)  or "0.0.0.0"
    helo      = _helo_domain(hdr) or "localhost"
    from_dom  = _from_domain(hdr) or "example.com"
    mfrom_dom = _mail_from_domain(hdr) or from_dom
    dkim_dom  = _dkim_domain(raw)

    spf_res  = _spf(ip, f"@{mfrom_dom}", helo)
    dkim_res = _dkim(raw)

    spf_ok  = spf_res == "pass" and mfrom_dom == from_dom
    dkim_ok = dkim_res == "pass" and dkim_dom and dkim_dom.endswith(from_dom)
    dmarc_res = _dmarc(from_dom, spf_ok, dkim_ok)

    verdict = (
        "Genuine"                  if dmarc_res == "pass"
        else "Likely Spoofed"      if spf_res == "fail" and dkim_res == "fail"
        else "Possibly Genuine but Suspicious"
    )

    auth = {"SPF": spf_res, "DKIM": dkim_res, "DMARC": dmarc_res}
    return verdict, auth, _field(hdr, "From") or "—", _field(hdr, "Reply-To") or "—"
