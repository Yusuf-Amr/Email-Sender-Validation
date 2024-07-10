import requests

def check_ip_reputation(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return f"Error fetching data from VirusTotal API: {response.status_code}"

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})

    reputation_score = attributes.get("reputation", "N/A")
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    malicious_count = last_analysis_stats.get("malicious", 0)
    suspicious_count = last_analysis_stats.get("suspicious", 0)
    harmless_count = last_analysis_stats.get("harmless", 0)
    undetected_count = last_analysis_stats.get("undetected", 0)

    malicious_vendors = []
    if "last_analysis_results" in attributes:
        last_analysis_results = attributes["last_analysis_results"]
        for vendor, result in last_analysis_results.items():
            if result["result"] not in ["clean", "unrated", "timeout"]:
                malicious_vendors.append((vendor, result["result"], result))

    result = {
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count": harmless_count,
        "undetected_count": undetected_count,
        "malicious_vendors": malicious_vendors
    }

    return result
