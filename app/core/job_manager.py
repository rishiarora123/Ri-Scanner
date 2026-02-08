import threading
import time
import queue
from typing import List, Dict, Any, Set

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
        
        # Start worker thread
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

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
                    # For now, just a placeholder or minimal processing
                    thread = threading.Thread(target=self._run_job, args=(domain,), daemon=True)
                    self.active_jobs[domain] = thread
                    thread.start()
                except queue.Empty:
                    break
            time.sleep(1)

    def _run_job(self, domain: str):
        # Placeholder for per-domain specific jobs if needed in the future
        time.sleep(1)

job_manager = JobManager()
