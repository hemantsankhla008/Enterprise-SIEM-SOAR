import random

# Mock Threat Intelligence & GeoIP Database
KNOWN_THREAT_DATABASE = {
    "192.168.1.100": {
        "threat_score": 90,
        "country": "Russia",
        "city": "Moscow",
        "isp": "DarkNet Hosting",
        "reputation": "MALICIOUS_SQLI_SOURCE"
    },
    "10.0.0.50": {
        "threat_score": 75,
        "country": "China",
        "city": "Beijing",
        "isp": "HostProviderX",
        "reputation": "KNOWN_BRUTEFORCER"
    },
    "192.168.1.105": {
        "threat_score": 95,
        "country": "Tor Exit Node",
        "city": "Unknown",
        "isp": "Anonymized Relay",
        "reputation": "ZERO_DAY_ANOMALY"
    }
}

def enrich_ip_intel(ip_address: str) -> dict:
    """
    Enriches incoming IP with GeoIP context and Threat Score.
    """
    if ip_address in KNOWN_THREAT_DATABASE:
        return KNOWN_THREAT_DATABASE[ip_address]
    
    # Internal/Local Network Handling
    if ip_address.startswith("127.") or ip_address.startswith("172.16"):
        return {
            "threat_score": 5,
            "country": "Internal Network",
            "city": "Local Subnet",
            "isp": "Private Infrastructure",
            "reputation": "CLEAN"
        }

    # External Dynamic IPs Fallback Context
    return {
        "threat_score": 25,
        "country": "India",
        "city": "Jaipur",
        "isp": "Regional Telecom",
        "reputation": "LOW_RISK"
    }