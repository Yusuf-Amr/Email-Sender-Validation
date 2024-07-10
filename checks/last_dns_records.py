from colorama import Fore, Style

def last_dns_records(records):
    try:
        if records:
            print(f"{Fore.BLUE}{Style.BRIGHT}\nVirusTotal Last DNS Records:{Style.RESET_ALL}")
            for record in records:
                record_type = record.get("type", "Unknown")
                record_value = record.get("value", "Unknown")
                print(f"{Fore.LIGHTCYAN_EX}Type: {record_type}, Value: {record_value}{Style.RESET_ALL}")
        else:
            print("No DNS records found for this domain.")
    except Exception as e:
        print(f"Error printing last DNS records: {e}")
