import spf

def check_spf(domain, ip, sender_email):
    try:
        result = spf.check2(i=ip, s=sender_email, h=domain)
        return result
    except Exception as e:
        return f"SPF FAILED: Error checking SPF: {e}"
