"""
Fuzzing Manager - Handles directory brute-forcing using ffuf.
"""
import os
import json
import asyncio
import shutil
import time
import threading
from typing import Dict, List, Optional, Any
from .tools_config import TOOLS

class FuzzingManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(FuzzingManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
            
        self._initialized = True
        self.active_scans: Dict[str, asyncio.Task] = {}
        self.db = None
        self.default_wordlist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists", "common.txt")

    def set_db(self, db):
        self.db = db

    def is_ffuf_installed(self) -> bool:
        return shutil.which("ffuf") is not None

    async def start_fuzzing(self, scan_id: str, domain: str, wordlist: Optional[str] = None):
        """
        Start a fuzzing scan for a domain.
        Args:
            scan_id: Main scan ID (or 'manual')
            domain: Target domain/URL
            wordlist: Path to wordlist
        """
        if not self.is_ffuf_installed():
            return {"success": False, "error": "ffuf is not installed"}

        job_id = f"{scan_id}_{domain}"
        if job_id in self.active_scans and not self.active_scans[job_id].done():
            return {"success": False, "error": "Fuzzing already in progress for this domain"}

        wlist = wordlist or self.default_wordlist
        if not os.path.exists(wlist):
            return {"success": False, "error": f"Wordlist not found: {wlist}"}

        # Normalize URL
        url = domain
        if not url.startswith("http"):
            url = f"https://{domain}"

        # Create output file
        if not os.path.exists("Tmp"): os.makedirs("Tmp")
        output_file = os.path.join("Tmp", f"ffuf_{int(time.time())}_{job_id}.json")

        cmd = f"ffuf -u {url}/FUZZ -w {wlist} -mc 200,301,302,403 -o {output_file} -of json -t 50 -timeout 5"
        
        print(f"[*] Starting Fuzzing: {cmd}")

        # Launch async task
        task = asyncio.create_task(self._run_ffuf_task(job_id, cmd, output_file, scan_id, domain))
        self.active_scans[job_id] = task
        
        return {"success": True, "job_id": job_id, "message": "Fuzzing started"}

    async def _run_ffuf_task(self, job_id, cmd, output_file, scan_id, domain):
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                print(f"[+] Fuzzing completed for {domain}")
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._parse_and_save_results, output_file, scan_id, domain)
            else:
                print(f"[!] Fuzzing failed for {domain}: {stderr.decode()}")

        except Exception as e:
            print(f"[!] Fuzzing error: {e}")
        finally:
            if job_id in self.active_scans:
                del self.active_scans[job_id]
            if os.path.exists(output_file):
                try: os.remove(output_file)
                except: pass

    def _parse_and_save_results(self, output_file, scan_id, domain):
        try:
            if not os.path.exists(output_file):
                return
                
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            results = data.get("results", [])
            if not results:
                return

            if self.db is None:
                print("[!] DB not connected in FuzzingManager")
                return

            timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
            ops = []
            from pymongo import UpdateOne
            
            for res in results:
                path = res.get("input", {}).get("FUZZ", "")
                full_url = res.get("url", "")
                status = res.get("status")
                length = res.get("length")
                words = res.get("words")
                
                doc = {
                    "scan_id": scan_id,
                    "domain": domain,
                    "path": path,
                    "url": full_url,
                    "status_code": status,
                    "length": length,
                    "words": words,
                    "content_type": res.get("content-type"),
                    "redirect_location": res.get("redirectlocation"),
                    "discovered_at": timestamp
                }
                
                ops.append(UpdateOne(
                    {"scan_id": scan_id, "domain": domain, "path": path},
                    {"$set": doc},
                    upsert=True
                ))

            if ops:
                self.db.fuzzing_results.bulk_write(ops)
                print(f"[+] Saved {len(ops)} fuzzing results for {domain}")

        except Exception as e:
            print(f"[!] Error parsing fuzzing results: {e}")

    def stop_fuzzing(self, domain, scan_id="manual"):
        job_id = f"{scan_id}_{domain}"
        if job_id in self.active_scans:
            task = self.active_scans[job_id]
            task.cancel()
            del self.active_scans[job_id]
            return True
        return False

# Global instance
fuzzing_manager = FuzzingManager()
