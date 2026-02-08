import re
import os
import json
import urllib.request
import threading
import ssl
import socket
import requests
from bs4 import BeautifulSoup

def is_valid_domain(common_name):
    # Regular expression pattern for a valid domain name
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(domain_pattern, common_name) is not None

def check_and_create_files(*file_paths):
    for file_path in file_paths:
        if not os.path.exists(file_path):
            # If the file doesn't exist, create it
            with open(file_path, "w") as file:
                pass
            # print(f'File "{file_path}" has been created.')

def log_to_server(message):
    """Sends a log message to the server for the dashboard verbose view."""
    def _send():
        try:
            data = json.dumps({"message": message}).encode('utf-8')
            req = urllib.request.Request("http://127.0.0.1:5000/log_update", data=data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()

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
        import requests
        url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
        response = requests.get(url, timeout=10)
        
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
        import requests
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
        response = requests.get(url, timeout=10)
        
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
        import requests
        import re
        
        url = f"https://bgp.he.net/AS{asn_num}#_prefixes"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            # Extract IP prefixes from HTML table
            # Pattern matches IPv4 and IPv6 CIDR notation
            pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}/\d{1,3}\b'
            prefixes = re.findall(pattern, response.text)
            return list(set(prefixes[:500]))  # Limit to 500 to avoid huge lists
    except Exception:
        pass
    return []

def get_ip_info(ip):
    """Get ASN and Organization for an IP using ip-api.com (free demo)."""
    try:
        import requests
        url = f"http://ip-api.com/json/{ip}?fields=status,message,as,org"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                # Example as: "AS15169 Google LLC"
                as_str = data.get("as", "")
                asn = as_str.split()[0] if as_str else "Unknown"
                return {"asn": asn, "org": data.get("org", "Unknown")}
    except Exception:
        pass
    return {"asn": "Unknown", "org": "Unknown"}
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
    import requests
    from bs4 import BeautifulSoup
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

        response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
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
