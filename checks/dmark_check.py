import dns.resolver

def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for txt_record in answers:
            if 'DMARK PASSED: v=DMARC1' in str(txt_record):
                return str(txt_record)
        return 'DMARK FAILED, No DMARC record found'
    except Exception as e:
        return f"DMARK FAILED: Error checking DMARC: {e}"
