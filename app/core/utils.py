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