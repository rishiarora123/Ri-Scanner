import re
import os
import json
import urllib.request
import threading

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
    Resolve ASN to a list of IP prefixes using whois.
    Example: AS15169 -> ['8.8.8.0/24', ...]
    """
    import subprocess
    asn = asn.upper().strip()
    if not asn.startswith("AS"):
        asn = f"AS{asn}"
    
    # Extract just the number for query
    asn_num = asn.replace("AS", "")
        
    try:
        # Using RADB for ASN prefix resolution
        # Use separate arguments for better cross-platform compatibility
        cmd = ["whois", "-h", "whois.radb.net", f"-i origin AS{asn_num}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        prefixes = []
        if result.returncode == 0:
            # Extract prefixes from the 'route:' or 'route6:' fields
            pattern = r"route6?:\s*([^\s]+)"
            prefixes = re.findall(pattern, result.stdout)
            
        return list(set(prefixes))  # Remove duplicates
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []