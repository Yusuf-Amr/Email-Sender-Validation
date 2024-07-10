from api_key import get_api_key, store_api_key
from checks.spf_check import check_spf
from checks.dmark_check import check_dmarc
from checks.virustotal_check import check_virustotal
from checks.whois_check import get_whois_info
from checks.last_dns_records import last_dns_records
from checks.ip_reputation import check_ip_reputation
from colorama import Fore, Style, init as colorama_init

# Initialize Colorama for colored output
colorama_init()
def main():
    api_key = get_api_key()
    if not api_key:
        store_api_key()
        api_key = get_api_key()

    while True:
        domain = input("\nEnter the domain: ")
        sender_email = input("\nEnter the sender's email address: ")
        ip = input("\nEnter the IP address to check the SPF and IP reputation: ")

        spf_result = check_spf(domain, ip, sender_email)
        dmarc_result = check_dmarc(domain)
        whois_info = get_whois_info(domain)
        vt_result = check_virustotal(domain, api_key)
        ip_reputation = check_ip_reputation(ip, api_key)
        #print spf and dmark
        
        print(f"{Fore.BLUE}{Style.BRIGHT}\nSPF Result:\n{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{spf_result}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{Style.BRIGHT}\nDMARC Result:\n{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{dmarc_result}{Style.RESET_ALL}")

        #print domain reputation and last dns records

        if vt_result:
            last_dns_records(vt_result.get("last_dns_records", {}))
            print(f"{Fore.BLUE}{Style.BRIGHT}\nVirusTotal Category:{Style.RESET_ALL}")
            print(f"{Fore.LIGHTCYAN_EX}{vt_result.get('category')}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}{Style.BRIGHT}\nVirusTotal Scan Results:{Style.RESET_ALL}")
            print(f"{Fore.RED}{Style.BRIGHT}Malicious: {vt_result.get('malicious_count')}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{Style.BRIGHT}Suspicious: {vt_result.get('suspicious_count')}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{Style.BRIGHT}Clean: {vt_result.get('clean_count')}{Style.RESET_ALL}")
            print(f"{Fore.BLACK}{Style.BRIGHT}Undetected: {vt_result.get('undetected_count')}{Style.RESET_ALL}")
            if vt_result.get("malicious_count") > 0:
                print(f"\n{Fore.BLUE}{Style.BRIGHT}Security Vendors Flagging the Domain as Malicious:{Style.RESET_ALL}")
                for vendor, value, details in vt_result.get("malicious_vendors", []):
                    print(f"{Fore.CYAN}{Style.BRIGHT}{vendor}{Style.RESET_ALL}: {Fore.RED}{Style.BRIGHT}{value}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}{Style.BRIGHT}No malicious security vendors flagged this domain.{Style.RESET_ALL}")

            print(f"\n{Fore.BLUE}{Style.BRIGHT}VirusTotal Popularity Ranks:\n{Style.RESET_ALL}")
            popularity_ranks = vt_result.get("popularity_ranks")
            if popularity_ranks:
                for key, value in popularity_ranks.items():
                    print(f"{Fore.LIGHTCYAN_EX}{key}: {value}{Style.RESET_ALL}")
            else:
                print(f"{Fore.LIGHTCYAN_EX}No popularity ranks found{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{Style.BRIGHT}VirusTotal results could not be retrieved. Please make sure you entered the domain correctly without spaces.{Style.RESET_ALL}")
         # Print IP reputation results
        print(f"{Fore.BLUE}{Style.BRIGHT}\nIP Reputation Results:{Style.RESET_ALL}")
        print(f"{Fore.RED}{Style.BRIGHT}Malicious: {ip_reputation.get('malicious_count')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}Suspicious: {ip_reputation.get('suspicious_count')}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{Style.BRIGHT}Clean: {ip_reputation.get('harmless_count')}{Style.RESET_ALL}")
        print(f"{Fore.BLACK}{Style.BRIGHT}Undetected: {ip_reputation.get('undetected_count')}{Style.RESET_ALL}")

        if ip_reputation.get("malicious_count") > 0:
            print(f"\n{Fore.BLUE}{Style.BRIGHT}Security Vendors Flagging the IP as Malicious:{Style.RESET_ALL}")
            for vendor, value, details in ip_reputation.get("malicious_vendors", []):
                print(f"{Fore.CYAN}{Style.BRIGHT}{vendor}{Style.RESET_ALL}: {Fore.RED}{Style.BRIGHT}{value}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}{Style.BRIGHT}No malicious security vendors flagged this IP.{Style.RESET_ALL}")
        #print whois
        print(f"\n{Fore.BLUE}{Style.BRIGHT}\nWHOIS Info:{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{whois_info}{Style.RESET_ALL}")


        # Ask if the user wants to check another domain
        continue_checking = input("Do you want to check another domain? (y/n): ").strip().lower()
        if continue_checking != "y":
            break

if __name__ == "__main__":
    main()
