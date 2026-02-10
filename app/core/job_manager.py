"""
Job Manager — Background task processor for subdomain probing.
When subdomains are discovered, they can be queued here to automatically
fetch HTTP status, title, technologies, and other metadata.
"""
import threading
import time
import queue
import requests
from typing import List, Dict, Any, Set
from bs4 import BeautifulSoup


class JobManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(JobManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
            
        self._initialized = True
        self.max_concurrent_jobs = 10
        self.job_queue = queue.Queue()
        self.active_jobs: Dict[str, threading.Thread] = {}
        self.completed_jobs: Set[str] = set()
        self.running = True
        self._db = None
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (Ri-Scanner Pro)"})
        
        # Start worker thread
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

    def set_db(self, db):
        """Set MongoDB reference for saving results."""
        self._db = db

    def add_jobs(self, domains: List[str]):
        """Add domains to the queue."""
        count = 0
        for domain in domains:
            if domain not in self.completed_jobs and domain not in self.active_jobs:
                self.job_queue.put(domain)
                count += 1
        return count

    def get_status(self) -> Dict[str, int]:
        return {
            "queued": self.job_queue.qsize(),
            "running": len(self.active_jobs),
            "completed": len(self.completed_jobs)
        }

    def _process_queue(self):
        while self.running:
            finished = [d for d, t in self.active_jobs.items() if not t.is_alive()]
            for d in finished:
                del self.active_jobs[d]
                self.completed_jobs.add(d)

            while len(self.active_jobs) < self.max_concurrent_jobs and not self.job_queue.empty():
                try:
                    domain = self.job_queue.get_nowait()
                    thread = threading.Thread(target=self._run_job, args=(domain,), daemon=True)
                    self.active_jobs[domain] = thread
                    thread.start()
                except queue.Empty:
                    break
            time.sleep(1)

    def _run_job(self, domain: str):
        """Probe a subdomain for HTTP status, title, and technologies."""
        details = {
            "status_code": None,
            "title": None,
            "technologies": [],
            "response_time_ms": None,
            "ip": None,
            "probed": True,
            "probed_at": time.strftime("%Y-%m-%dT%H:%M:%S")
        }

        # Try HTTPS first, then HTTP
        for protocol in ["https", "http"]:
            url = f"{protocol}://{domain}"
            try:
                start = time.time()
                resp = self._session.get(url, timeout=8, verify=False, allow_redirects=True)
                elapsed_ms = int((time.time() - start) * 1000)

                details["status_code"] = resp.status_code
                details["response_time_ms"] = elapsed_ms

                # Parse title
                try:
                    soup = BeautifulSoup(resp.text[:50000], "html.parser")
                    if soup.title:
                        details["title"] = soup.title.get_text().strip()[:200]
                except Exception:
                    pass

                # Detect technologies from headers/body
                techs = set()
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

                server = headers.get("server", "")
                if "nginx" in server: techs.add("Nginx")
                if "apache" in server: techs.add("Apache")
                if "cloudflare" in server: techs.add("Cloudflare")
                if "microsoft-iis" in server: techs.add("IIS")

                powered = headers.get("x-powered-by", "")
                if "php" in powered: techs.add("PHP")
                if "asp.net" in powered: techs.add("ASP.NET")
                if "express" in powered: techs.add("Express.js")

                body = resp.text[:100000].lower()
                if "wp-content" in body or "wordpress" in body: techs.add("WordPress")
                if "react" in body: techs.add("React")
                if "vue" in body: techs.add("Vue.js")
                if "jquery" in body: techs.add("jQuery")
                if "bootstrap" in body: techs.add("Bootstrap")
                if "next.js" in body or "__next" in body: techs.add("Next.js")
                if "laravel" in body: techs.add("Laravel")

                details["technologies"] = list(techs)
                break  # Success — don't try the other protocol

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                details["status_code"] = None
                details["title"] = "Timeout"
                continue
            except Exception:
                continue

        # Resolve IP
        try:
            import socket
            details["ip"] = socket.gethostbyname(domain)
        except Exception:
            pass

        # Save to MongoDB
        if self._db is not None:
            try:
                self._db.subdomains.update_one(
                    {"domain": domain},
                    {"$set": details},
                    upsert=False  # Only update existing records
                )
            except Exception as e:
                print(f"[!] Job DB error for {domain}: {e}")


job_manager = JobManager()
