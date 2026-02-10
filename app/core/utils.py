import re
import os
import json
import ssl
import socket
import time
import requests
from bs4 import BeautifulSoup

# ── IP Info Cache ─────────────────────────────────────────────────
_ip_info_cache = {}
_ip_info_cache_ttl = 300  # 5 minutes
_ip_api_last_call = 0
_IP_API_MIN_INTERVAL = 1.4  # ~43 req/min (free tier limit is 45/min)


def is_valid_domain(common_name):
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(domain_pattern, common_name) is not None


def check_and_create_files(*file_paths):
    for file_path in file_paths:
        if not os.path.exists(file_path):
            with open(file_path, "w") as file:
                pass


# ── Reusable Session ──────────────────────────────────────────────
_session = None

def _get_session():
    """Reuse a requests.Session for connection pooling."""
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({"User-Agent": "Mozilla/5.0 (Ri-Scanner Pro)"})
    return _session


# ── ASN Resolution ────────────────────────────────────────────────

def resolve_asn_to_ips(asn):
    """
    Resolve ASN to IP prefixes using multiple fallback methods.
    Tries: BGPView API → RIPEstat API → HE BGP Toolkit
    
    Example: AS15169 -> ['8.8.8.0/24', ...]
    """
    asn = asn.upper().strip()
    if not asn.startswith("AS"):
        asn = f"AS{asn}"
    
    asn_num = asn.replace("AS", "")
    
    # Method 1: Try BGPView API (fast, but might be blocked)
    prefixes = _try_bgpview(asn_num)
    if prefixes:
        print(f"[+] Resolved {asn} using BGPView: {len(prefixes)} prefixes")
        return prefixes
    
    # Method 2: Try RIPEstat API (reliable, global coverage)
    prefixes = _try_ripestat(asn_num)
    if prefixes:
        print(f"[+] Resolved {asn} using RIPEstat: {len(prefixes)} prefixes")
        return prefixes
    
    # Method 3: Try Hurricane Electric BGP Toolkit (web scraping fallback)
    prefixes = _try_hurricane_electric(asn_num)
    if prefixes:
        print(f"[+] Resolved {asn} using HE BGP: {len(prefixes)} prefixes")
        return prefixes
    
    print(f"[!] Could not resolve {asn} - all methods failed")
    return []


def _try_bgpview(asn_num):
    """Try BGPView API"""
    try:
        session = _get_session()
        url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
        response = session.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok" and "data" in data:
                prefixes = []
                for item in data["data"].get("ipv4_prefixes", []):
                    if "prefix" in item:
                        prefixes.append(item["prefix"])
                for item in data["data"].get("ipv6_prefixes", []):
                    if "prefix" in item:
                        prefixes.append(item["prefix"])
                return list(set(prefixes))
    except Exception:
        pass
    return []


def _try_ripestat(asn_num):
    """Try RIPEstat API (more reliable, works globally)"""
    try:
        session = _get_session()
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
        response = session.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok" and "data" in data:
                prefixes = []
                for item in data["data"].get("prefixes", []):
                    if "prefix" in item:
                        prefixes.append(item["prefix"])
                return list(set(prefixes))
    except Exception:
        pass
    return []


def _try_hurricane_electric(asn_num):
    """Try Hurricane Electric BGP Toolkit (web scraping as last resort)"""
    try:
        session = _get_session()
        url = f"https://bgp.he.net/AS{asn_num}#_prefixes"
        response = session.get(url, timeout=15)
        
        if response.status_code == 200:
            pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}/\d{1,3}\b'
            prefixes = re.findall(pattern, response.text)
            return list(set(prefixes[:500]))
    except Exception:
        pass
    return []


# ── IP Info ───────────────────────────────────────────────────────

def get_ip_info(ip):
    """Get ASN, Organization, and Country for an IP using ip-api.com (free demo).
    Results are cached for 5 minutes. Rate-limited to ~43 req/min."""
    global _ip_api_last_call
    
    # Check cache first
    if ip in _ip_info_cache:
        entry = _ip_info_cache[ip]
        if time.time() - entry["ts"] < _ip_info_cache_ttl:
            return entry["data"]
    
    # Rate limiting
    now = time.time()
    elapsed = now - _ip_api_last_call
    if elapsed < _IP_API_MIN_INTERVAL:
        time.sleep(_IP_API_MIN_INTERVAL - elapsed)
    
    try:
        session = _get_session()
        url = f"http://ip-api.com/json/{ip}?fields=status,message,as,org,country"
        response = session.get(url, timeout=5)
        _ip_api_last_call = time.time()
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                as_str = data.get("as", "")
                asn = as_str.split()[0] if as_str else "Unknown"
                result = {
                    "asn": asn,
                    "org": data.get("org", "Unknown"),
                    "country": data.get("country", "Unknown")
                }
                _ip_info_cache[ip] = {"data": result, "ts": time.time()}
                return result
    except Exception:
        pass
    
    fallback = {"asn": "Unknown", "org": "Unknown", "country": "Unknown"}
    _ip_info_cache[ip] = {"data": fallback, "ts": time.time()}
    return fallback


# ── SSL / Service Analysis ────────────────────────────────────────

def get_ssl_cn(ip, port=443):
    """Extract Common Name from SSL certificate."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if cert and 'subject' in cert:
                    for item in cert['subject']:
                        for key, value in item:
                            if key == 'commonName':
                                return value
    except Exception:
        pass
    return None


def analyze_service(ip, port):
    """Perform HTTP/HTTPS analysis to extract title, tech stack, and headers."""
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}"
    
    result = {
        "url": url,
        "status_code": None,
        "title": "No Title",
        "headers": {},
        "technologies": [],
        "domain": None,
        "ssl_cn": None
    }

    if port == 27017:
        result["title"] = "MongoDB Discovery"
        result["technologies"] = ["MongoDB"]
        return result

    try:
        if protocol == "https":
            cn = get_ssl_cn(ip, port)
            result["ssl_cn"] = cn
            result["domain"] = cn

        session = _get_session()
        response = session.get(url, timeout=5, verify=False, allow_redirects=True)
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.title:
            result["title"] = soup.title.get_text().strip()
            
        techs = set()
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        server = headers_lower.get("server", "")
        if "nginx" in server: techs.add("Nginx")
        if "apache" in server: techs.add("Apache")
        if "microsoft-iis" in server: techs.add("IIS")
        if "cloudflare" in server: techs.add("Cloudflare")
        
        powered = headers_lower.get("x-powered-by", "")
        if "php" in powered: techs.add("PHP")
        if "asp.net" in powered: techs.add("ASP.NET")
        
        cookies = headers_lower.get("set-cookie", "")
        if "phpsessid" in cookies: techs.add("PHP")
        if "jsessionid" in cookies: techs.add("Java")
        if "wp-settings" in cookies: techs.add("WordPress")
        
        body = response.text.lower()
        if "wp-content" in body or "wordpress" in body: techs.add("WordPress")
        if "react" in body: techs.add("React")
        if "vue" in body: techs.add("Vue.js")
        if "jquery" in body: techs.add("jQuery")
        if "bootstrap" in body: techs.add("Bootstrap")
        
        result["technologies"] = list(techs)
    except Exception:
        pass
    return result
