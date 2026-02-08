import os
import sys
import webbrowser
import threading
import time
import signal
import atexit
import subprocess
import shutil
from app import create_app

def cleanup_handler(sig=None, frame=None):
    """Clean up temporary files and caches on exit."""
    print("\n[*] Cleaning up temporary files...")
    
    cleanup_paths = [
        "Data",
        "Tmp", 
        "app/__pycache__",
        "app/core/__pycache__"
    ]
    
    for path in cleanup_paths:
        if os.path.exists(path):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                    print(f"[✓] Removed {path}")
                else:
                    os.remove(path)
                    print(f"[✓] Removed {path}")
            except Exception as e:
                print(f"[!] Could not remove {path}: {e}")
    
    # Kill any stray masscan processes
    try:
        subprocess.run(["sudo", "killall", "-q", "masscan"], 
                      stdout=subprocess.DEVNULL, 
                      stderr=subprocess.DEVNULL)
    except:
        pass
    
    if sig is not None:
        sys.exit(0)

def check_sudo():
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for Masscan. Please run with sudo.")
        sys.exit(1)

def open_browser():
    time.sleep(2)
    try:
        webbrowser.open("http://127.0.0.1:5000/")
    except Exception:
        pass

if __name__ == "__main__":
    check_sudo()
    
    # Register cleanup handlers
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)
    atexit.register(cleanup_handler)
    
    app = create_app()
    
    # Open browser in a separate thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    print("[*] Starting Ri-Scanner Pro...")
    print("[*] Dashboard available at http://127.0.0.1:5000/")
    print("[*] Press Ctrl+C to stop and auto-cleanup")
    
    # Disable reloader to prevent double execution of browser/threads
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)