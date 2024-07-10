import requests
import json

def check_virustotal(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Error fetching data from VirusTotal API: {response.status_code}")
        return None

    data = response.json()

    # Extract required fields from VirusTotal response
    attributes = data.get("data", {}).get("attributes", {})

    last_dns_records = attributes.get("last_dns_records", {})

    # Extract analysis stats
    analysis_stats = attributes.get("last_analysis_stats", {})
    malicious_count = analysis_stats.get("malicious", 0)
    suspicious_count = analysis_stats.get("suspicious", 0)
    clean_count = analysis_stats.get("undetected", 0) + analysis_stats.get("harmless", 0)

    # Extract malicious security vendors with details and value
    malicious_vendors = []
    if "last_analysis_results" in attributes:
        last_analysis_results = attributes["last_analysis_results"]
        for vendor, result in last_analysis_results.items():
            if result["result"] not in ["clean", "unrated", "timeout"]:
                malicious_vendors.append((vendor, result["result"], result))

    # Extract category
    category = attributes.get("categories", [])

    # Extract popularity ranks
    popularity_ranks = attributes.get("popularity_ranks", {})

    # Format the output as required
    result = {
        "last_dns_records": last_dns_records,
        "malicious_count": malicious_count,
        "malicious_vendors": malicious_vendors,
        "clean_count": clean_count,
        "category": category,
        "popularity_ranks": popularity_ranks,
        "suspicious_count": suspicious_count
    }

    return result
