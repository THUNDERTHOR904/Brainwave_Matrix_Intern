import re
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime

GOOGLE_API_KEY = 'AIzaSyAh9jKWWIb005lTRvUmquhOCiIbVs3JDWM'  
VT_API_KEY = '18f668cede99fe57bd0061394343a95f420db42173e8fd084ed58d2de9aa469d'      

def is_suspicious_url(url):
    parsed = urlparse(url)
    hostname = parsed.netloc

    suspicious_signs = [
        len(url) > 75,
        "@" in url,
        "-" in hostname,
        url.count("http") > 1,
        re.search(r"\d{1,3}(?:\.\d{1,3}){3}", hostname),  
        re.search(r"(login|verify|update|secure|banking)", url, re.IGNORECASE),
    ]

    return any(suspicious_signs)

def check_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1
        age_days = (datetime.now() - creation_date).days
        return age_days
    except Exception as e:
        return -1  

def check_google_safe_browsing(url):
    if not GOOGLE_API_KEY:
        return "🔒 Google Safe Browsing: API Key not set."

    payload = {
        "client": {
            "clientId": "phishing-scanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(
        f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}',
        json=payload
    )

    if response.status_code == 200:
        if response.json():
            return "❌ Google Safe Browsing: Threat detected!"
        else:
            return "✅ Google Safe Browsing: URL is safe."
    return f"❌ Google API Error: {response.status_code}"

def check_virustotal(url):
    if not VT_API_KEY:
        return "🔒 VirusTotal: API Key not set."

    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if response.status_code == 200:
        result = response.json()
        url_id = result['data']['id']
        report_url = f"https://www.virustotal.com/gui/url/{url_id}"
        return f"🔎 VirusTotal report: {report_url}"
    else:
        return f"❌ VirusTotal API Error: {response.status_code}"

def main():
    url = input("🔍 Enter a URL to scan: ").strip()
    parsed = urlparse(url)
    domain = parsed.netloc

    print("\n[+] Analyzing URL...\n")

    # Heuristic check
    if is_suspicious_url(url):
        print("⚠️  Suspicious patterns detected in URL.")
    else:
        print("✅ URL structure looks clean.")

    # Domain age check
    domain_age = check_domain_age(domain)
    if domain_age == -1:
        print("❌ Could not retrieve domain age.")
    elif domain_age < 180:
        print(f"⚠️  Domain is relatively new ({domain_age} days old).")
    else:
        print(f"✅ Domain is {domain_age} days old — likely established.")

    # Google Safe Browsing API check
    print(check_google_safe_browsing(url))

    # VirusTotal check
    print(check_virustotal(url))

if __name__ == "__main__":
    main()
