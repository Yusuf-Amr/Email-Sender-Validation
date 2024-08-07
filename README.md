## Email Sender Validation Tool

This Python script provides a set of tools for analyzing email-related data including SPF, DMARC, VirusTotal Domain and IP reputation, WHOIS information, and more. It's designed to assist SOC (Security Operations Center) analysts in quickly assessing the legitimacy and potential risks associated with email communications.

## Features

    - SPF Check: Validates the Sender Policy Framework (SPF) records for a domain against an IP and sender email address.

    - VirusTotal Check: Retrieves domain-related and IP data from VirusTotal API including last DNS records, categories, and security scan results.

    - WHOIS Lookup: Fetches WHOIS information for a domain to ascertain ownership and registration details.

    - DMARC Check (Optional): Retrieves DMARC records for a domain.


## Usage

VirusTotal API Key Setup:

    - When you run the script for the first time, it will prompt you to enter your VirusTotal API key.
    - The API key will be automatically saved in api_key.txt and will not prompt for it again in future runs.
    - To change the API key, update it directly in api_key.txt.

## Requirements

    Python 3.x
    Libraries:
        colorama
        requests
        whois
        dns.resolver
        spf
        
## Installation

    Clone the repository: 
    - git clone https://github.com/Yusuf-Amr/email-sender-validation.git


Install dependencies:

    pip install -r requirements.txt

Run the script:

    python main.py

### Demo

**Real World Phishing Example:**

Source: https://x.com/phishunt_io/status/1780834586106167631

![The Phishing Mail Example](https://github.com/Yusuf-Amr/email-sender-validation/raw/main/demo_images/phishing%20example.png)

In this example, the sender domain is attempting to spoof the legitimate domain of Microsoft (microsoft.com): `bpg-microsoft(.)com`.

Sender IP: `217.160.14.242`

We do not have the full sender address, so we use: `bpg-microsoft(.)com`.

**Results:**

1. ![Result 1](https://github.com/Yusuf-Amr/email-sender-validation/raw/main/demo_images/1.png)

2. ![Result 2](https://github.com/Yusuf-Amr/email-sender-validation/raw/main/demo_images/2.png)

3. ![Result 3](https://github.com/Yusuf-Amr/email-sender-validation/raw/main/demo_images/3.png)

