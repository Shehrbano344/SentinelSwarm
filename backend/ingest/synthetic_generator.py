import requests
import random
import time
from datetime import datetime

BENIGN_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.22", "8.8.8.8", "1.1.1.1"]
MALICIOUS_IPS = ["193.142.146.35", "103.145.13.133", "45.134.144.150"] # fallback bad IPs
BENIGN_DOMAINS = ["google.com", "microsoft.com", "amazon.com", "internal-app.local"]
MALICIOUS_DOMAINS = ["malicious-c2-domain.com", "phishing-login-page.net"]

ALERTS = [
    {
        "source": "Firewall",
        "raw_log": "Connection refused from {ip} on port 22",
        "type": "IP_ONLY",
        "is_bad": False
    },
    {
        "source": "Endpoint",
        "raw_log": "Suspicious PowerShell command executed downloading payload from {domain}",
        "type": "DOMAIN_ONLY",
        "is_bad": True
    },
    {
        "source": "IDS",
        "raw_log": "Potential SQL Injection detected originating from {ip}",
        "type": "IP_ONLY",
        "is_bad": True
    },
    {
        "source": "Proxy",
        "raw_log": "User accessed known file sharing site {domain}",
        "type": "DOMAIN_ONLY",
        "is_bad": False
    },
    {
        "source": "Authentication",
        "raw_log": "Failed login attempt for user admin from {ip}",
        "type": "IP_ONLY",
        "is_bad": False
    }
]

def get_real_malicious_ip():
    """Fetch a real recent malicious IP from URLhaus."""
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/urls/recent/", data={"limit": 5}, timeout=5)
        if resp.status_code == 200:
            urls = resp.json().get("urls", [])
            for u in urls:
                host = u.get("host", "")
                # crude check if it's an IP
                if host.replace(".", "").isdigit():
                    return host
    except Exception:
        pass
    return None

def generate_alert():
    template = random.choice(ALERTS)
    alert = {
        "source": template["source"],
        "timestamp": datetime.utcnow().isoformat()
    }
    
    is_bad = template["is_bad"]
    
    if template["type"] == "IP_ONLY":
        ip = None
        if is_bad:
            # Try to get a real malicious IP 50% of the time to seed critical alerts
            if random.random() > 0.5:
                ip = get_real_malicious_ip()
            if not ip:
                ip = random.choice(MALICIOUS_IPS)
        else:
            ip = random.choice(BENIGN_IPS)
            
        alert["ip_address"] = ip
        alert["raw_log"] = template["raw_log"].format(ip=ip)
        
    elif template["type"] == "DOMAIN_ONLY":
        domain = random.choice(MALICIOUS_DOMAINS) if is_bad else random.choice(BENIGN_DOMAINS)
        alert["domain"] = domain
        alert["raw_log"] = template["raw_log"].format(domain=domain)

    return alert

def main():
    print("Generating synthetic alerts...")
    API_URL = "http://localhost:8000/alerts/"
    
    for i in range(15):
        alert_data = generate_alert()
        try:
            response = requests.post(API_URL, json=alert_data, timeout=5)
            response.raise_for_status()
            print(f"Generated alert ID: {response.json().get('id')} - Source: {alert_data['source']}")
        except requests.exceptions.RequestException as e:
            print(f"Failed to submit alert. Is the backend running? ({e})")
        time.sleep(0.5)

if __name__ == "__main__":
    main()
