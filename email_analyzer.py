import re
import spf
import dkim
import dns. resolver

# STEP 1: Load full raw email
def load_raw_email(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

# STEP 2: Extract header (from raw email)
def extract_header_from_raw(raw_email):
    # Split raw email by blank line → headers are before first blank line
    header_part = raw_email.split(b"\r\n\r\n", 1)[0]
    header_text = header_part.decode("utf-8", errors="replace")
    print("\n=== Extracted Header ===")
    print(header_text)
    return header_text

# STEP 3: Extract sending IP from Received header
def extract_sending_ip(header):
    received_matches = re.findall(r'Received: from .* \[(\d+\.\d+\.\d+\.\d+)\]', header)
    if received_matches:
        sending_ip = received_matches[-1]
        print("Extracted sending IP:", sending_ip)
        return sending_ip
    else:
        print("Could not find sending IP.")
        return None

# STEP 4: Extract HELO domain from Received header
def extract_helo_domain(header):
    match = re.search(r'Received: from (\S+)', header)
    if match:
        helo_domain = match.group(1)
        print("Extracted HELO domain:", helo_domain)
        return helo_domain
    else:
        print("Could not find HELO domain.")
        return None

# STEP 5: Perform SPF check
def perform_spf_check(sending_ip, sender, helo):
    try:
        result, code, explanation = spf.check2(i=sending_ip, s=sender, h=helo)
        print("SPF result:", result)
        return result
    except Exception as e:
        print("SPF check failed:", e)
        return "fail"

# STEP 6: Perform DKIM check
def perform_dkim_check(raw_email):
    try:
        valid = dkim.verify(raw_email)
        print("DKIM valid:", valid)
        return "pass" if valid else "fail"
    except Exception as e:
        print("DKIM check failed:", e)
        return "fail"

# STEP 7: Perform DMARC check
def perform_dmarc_check(domain):
    dmarc_domain = "_dmarc." + domain
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                print("DMARC record:", txt_string.decode())
                if "p=reject" in txt_string.decode() or "p=quarantine" in txt_string.decode():
                    return "pass"
        return "fail"
    except Exception as e:
        print("DMARC check failed or not found:", e)
        return "fail"

# STEP 8: Extract From and Reply-To
def extract_from_and_reply_to(header):
    from_match = re.search(r'From: (.*)', header)
    reply_to_match = re.search(r'Reply-To: (.*)', header)

    from_email = from_match.group(1) if from_match else "unknown"
    reply_to_email = reply_to_match.group(1) if reply_to_match else from_email

    return from_email, reply_to_email

# STEP 9: Is Reply-To suspicious?
def is_reply_to_suspicious(from_email, reply_to_email):
    return from_email != reply_to_email

# STEP 10: Final decision logic
def is_genuine(result):
    if result["SPF"] == "pass" and result["DKIM"] == "pass" and result["DMARC"] == "pass":
        return "Likely Genuine"
    elif result["DMARC"] == "fail":
        return "Likely Spoofed (DMARC failed)"
    elif result["SPF"] == "fail" and result["DKIM"] == "fail" and result["DMARC"] == "fail":
        return "Almost surely Fake"
    elif result["SPF"] == "fail" or result["DKIM"] == "fail":
        if result["DMARC"] == "pass":
            return "Possibly Genuine but Suspicious (forwarded?)"
        else:
            return "Suspicious"
    else:
        return "Unknown / Needs Manual Review"

# STEP 11: Combined analyze (ONLY raw email input)
def analyze_email(raw_email):
    header_text = extract_header_from_raw(raw_email)

    sending_ip = extract_sending_ip(header_text) or "127.0.0.1"  # Fallback
    helo_domain = extract_helo_domain(header_text) or "localhost"  # Fallback

    from_email, _ = extract_from_and_reply_to(header_text)
    if "<" in from_email and ">" in from_email:
        sender_email = re.search(r'<(.*)>', from_email).group(1)
    else:
        sender_email = from_email.strip()

    domain = sender_email.split("@")[1] if "@" in sender_email else "example.com"

    spf_result = perform_spf_check(sending_ip, sender_email, helo_domain)
    dkim_result = perform_dkim_check(raw_email)
    dmarc_result = perform_dmarc_check(domain)

    auth_result = {
        "SPF": "pass" if spf_result == "pass" else "fail",
        "DKIM": dkim_result,
        "DMARC": dmarc_result
    }

    from_email, reply_to_email = extract_from_and_reply_to(header_text)
    reply_to_suspicious = is_reply_to_suspicious(from_email, reply_to_email)

    decision = is_genuine(auth_result)
    if reply_to_suspicious:
        decision += " + Reply-To Mismatch (High Risk)"

    return decision, auth_result, from_email, reply_to_email

# For testing manually
if __name__ == "__main__":
    raw_file = input("Enter raw email file (.eml): ")
    raw_email = load_raw_email(raw_file)
    decision, auth_result, from_email, reply_to_email = analyze_email(raw_email)

    print("\n=== Authentication Results ===")
    print(f"SPF: {auth_result['SPF']}")
    print(f"DKIM: {auth_result['DKIM']}")
    print(f"DMARC: {auth_result['DMARC']}")

    print("\n=== From / Reply-To ===")
    print(f"From: {from_email}")
    print(f"Reply-To: {reply_to_email}")

    print("\n=== FINAL DECISION ===")
    print(decision)
