import requests
import time
from typing import Dict, Any, List

# TTL Cache dictionary: { "ioc_value": (timestamp, result_dict) }
_cache = {}
CACHE_TTL = 3600 # 1 hour

def _get_from_cache(ioc: str) -> Dict[str, Any]:
    if ioc in _cache:
        timestamp, result = _cache[ioc]
        if time.time() - timestamp < CACHE_TTL:
            return result
    return None

def _save_to_cache(ioc: str, result: Dict[str, Any]):
    _cache[ioc] = (time.time(), result)

def query_threatfox(ioc: str) -> Dict[str, Any]:
    """Query ThreatFox API for a given IOC."""
    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                # Return just the most relevant info to save context window
                first_match = data.get("data", [])[0]
                return {
                    "source": "ThreatFox", 
                    "threat_type": first_match.get("threat_type"),
                    "malware_printable": first_match.get("malware_printable"),
                    "confidence_level": first_match.get("confidence_level")
                }
    except Exception as e:
        print(f"ThreatFox Error: {e}")
    return None

def query_urlhaus(ioc: str) -> Dict[str, Any]:
    """Query URLhaus API for a host (IP or domain)."""
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ioc},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                # Filter useful info
                urls = data.get("urls", [])
                return {
                    "source": "URLhaus", 
                    "first_seen": data.get("firstseen"),
                    "url_count": len(urls),
                    "tags": list(set([tag for u in urls for tag in (u.get("tags") or [])]))
                }
    except Exception as e:
        print(f"URLhaus Error: {e}")
    return None

def enrich_ioc(ioc: str, ioc_type: str = "unknown") -> Dict[str, Any]:
    """
    Enrich an IOC using abuse.ch APIs (ThreatFox and URLhaus).
    Returns a dictionary of findings, or notes if unavailable/benign.
    """
    if not ioc:
        return {"error": "No IOC provided"}
        
    cached = _get_from_cache(ioc)
    if cached:
        return cached

    findings = []
    
    # Check ThreatFox
    tf_result = query_threatfox(ioc)
    if tf_result:
        findings.append(tf_result)
        
    # Check URLhaus (good for IP and Domain)
    if ioc_type in ["ip", "domain", "unknown"]:
        uh_result = query_urlhaus(ioc)
        if uh_result:
            findings.append(uh_result)

    if not findings:
        result = {
            "ioc": ioc,
            "malicious": False,
            "message": "No matches found on ThreatFox or URLhaus. API might be unreachable, or indicator is clean."
        }
    else:
        result = {
            "ioc": ioc,
            "malicious": True,
            "findings": findings
        }
    
    _save_to_cache(ioc, result)
    return result
