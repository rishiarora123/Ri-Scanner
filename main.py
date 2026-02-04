import os
import sys
import webbrowser
import threading
import time
from app import create_app

def check_sudo():
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for Masscan. Please run with sudo.")
        sys.exit(1)

def open_browser():
    time.sleep(2)
    try:
        webbrowser.open("http://127.0.0.1:5000/")
    except:
        pass

if __name__ == "__main__":
    check_sudo()
    
    app = create_app()
    
    # Open browser in a separate thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    print("[*] Starting Antigravity Scanner...")
    print("[*] Dashboard available at http://127.0.0.1:5000/")
    
    # Disable reloader to prevent double execution of browser/threads
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)