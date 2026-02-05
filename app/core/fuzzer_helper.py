import asyncio
import aiohttp
import time
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

class AsyncFuzzer:
    """
    High-performance asynchronous directory fuzzer.
    """
    def __init__(self, targets: List[str], wordlist_path: str, concurrency: int = 50, timeout: int = 10):
        self.targets = targets
        self.wordlist_path = wordlist_path
        self.concurrency = concurrency
        self.timeout = timeout
        self.results = []
        self.active_jobs = {}
        self._stop_event = asyncio.Event()

    async def _load_wordlist(self) -> List[str]:
        """Loads and cleans the wordlist."""
        if not os.path.exists(self.wordlist_path):
            return ["robots.txt", ".git/config", ".env", "admin/", "api/"]
        
        try:
            with open(self.wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            return ["robots.txt", ".git/config", ".env", "admin/", "api/"]

    def _normalize_url(self, target: str) -> str:
        """Ensures the target has a scheme and trailing slash removed."""
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        return target.rstrip('/')

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Performs a single HTTP request and returns results if interesting."""
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=False, ssl=False) as response:
                status = response.status
                # Interesting: 200, 204, 301, 302, 307, 403, 405
                if status in [200, 204, 301, 302, 307, 403, 405]:
                    return {
                        "url": url,
                        "status": status,
                        "length": response.content_length,
                        "type": response.headers.get("Content-Type", "").split(";")[0]
                    }
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            pass
        except Exception:
            pass
        return None

    async def fuzz_target(self, target: str, paths: List[str], progress_callback=None):
        """Fuzzes a single target against the wordlist."""
        target_url = self._normalize_url(target)
        semaphore = asyncio.Semaphore(self.concurrency)
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "Ri-Scanner/Pro"}) as session:
            tasks = []
            
            async def bounded_fetch(path):
                async with semaphore:
                    if self._stop_event.is_set():
                        return
                    url = f"{target_url}/{path.lstrip('/')}"
                    res = await self._fetch(session, url)
                    if res:
                        self.results.append(res)
                        if progress_callback:
                            try:
                                await progress_callback(target, res)
                            except Exception:
                                pass

            for path in paths:
                tasks.append(bounded_fetch(path))
            
            await asyncio.gather(*tasks, return_exceptions=True)

    async def run(self, progress_callback=None):
        """Runs the fuzzer across all targets."""
        paths = await self._load_wordlist()
        tasks = [self.fuzz_target(target, paths, progress_callback) for target in self.targets]
        await asyncio.gather(*tasks)

    def stop(self):
        """Stops the fuzzing process."""
        self._stop_event.set()


class DirectoryFuzzer:
    """
    Directory fuzzer with file storage and auto-queue support.
    """
    
    def __init__(self, base_dir: str = "Data/subdomains", wordlist_path: str = "Data/wordlists/directories.txt"):
        self.base_dir = base_dir
        self.wordlist_path = wordlist_path
        self.active_jobs = {}
    
    async def fuzz_domain(self, scan_id: str, domain: str, concurrency: int = 30) -> Dict:
        """
        Fuzz a single domain and save results.
        
        Returns:
            Dict with status, total_found, results
        """
        result = {
            "domain": domain,
            "status": "running",
            "total_found": 0,
            "results": [],
            "started_at": datetime.now().isoformat()
        }
        
        try:
            # Create fuzzer
            fuzzer = AsyncFuzzer(
                targets=[domain],
                wordlist_path=self.wordlist_path,
                concurrency=concurrency,
                timeout=10
            )
            
            # Track job
            self.active_jobs[domain] = fuzzer
            
            # Run fuzzing
            await fuzzer.run()
            
            # Get results
            result["results"] = fuzzer.results
            result["total_found"] = len(fuzzer.results)
            result["status"] = "completed"
            result["completed_at"] = datetime.now().isoformat()
            
            # Save to file
            self.save_fuzzing_results(scan_id, domain, result)
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        finally:
            self.active_jobs.pop(domain, None)
        
        return result
    
    def get_results(self, scan_id: str, domain: str, status_filter: Optional[str] = None, search_term: Optional[str] = None) -> List[Dict]:
        """
        Get fuzzing results with filters.
        
        Args:
            scan_id: Scan identifier
            domain: Domain name
            status_filter: Filter by status code range (2xx, 3xx, 4xx, 5xx)
            search_term: Search in URL path
        """
        try:
            file_path = os.path.join(self.base_dir, scan_id, "fuzzing_results.json")
            if not os.path.exists(file_path):
                return []
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            domain_data = data.get(domain, {})
            results = domain_data.get("results", [])
            
            # Apply filters
            if status_filter:
                status_range = self._parse_status_filter(status_filter)
                results = [r for r in results if r.get("status") in status_range]
            
            if search_term:
                term = search_term.lower()
                results = [r for r in results if term in r.get("url", "").lower()]
            
            return results
        except Exception as e:
            print(f"Error getting fuzzing results: {e}")
            return []
    
    def _parse_status_filter(self, filter_str: str) -> List[int]:
        """Parse status filter like '2xx' into list of codes."""
        if filter_str == "2xx":
            return [200, 201, 202, 203, 204]
        elif filter_str == "3xx":
            return [300, 301, 302, 303, 304, 307, 308]
        elif filter_str == "4xx":
            return [400, 401, 403, 404, 405, 406, 407, 408, 409]
        elif filter_str == "5xx":
            return [500, 501, 502, 503, 504, 505]
        return []
    
    async def auto_fuzz_queue(self, scan_id: str, domain_list: List[str]) -> None:
        """
        Auto-fuzz a queue of domains in background.
        
        Args:
            scan_id: Scan identifier
            domain_list: List of domains to fuzz
        """
        for domain in domain_list:
            try:
                await self.fuzz_domain(scan_id, domain)
            except Exception as e:
                print(f"Error fuzzing {domain}: {e}")
    
    def save_fuzzing_results(self, scan_id: str, domain: str, results: Dict) -> bool:
        """Save fuzzing results to file."""
        try:
            scan_dir = os.path.join(self.base_dir, scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            
            file_path = os.path.join(scan_dir, "fuzzing_results.json")
            
            # Load existing
            data = {}
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
            
            # Add new results
            data[domain] = results
            
            # Save
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving fuzzing results: {e}")
            return False
    
    def get_fuzzing_status(self, domain: str) -> Optional[str]:
        """Check if domain is currently being fuzzed."""
        if domain in self.active_jobs:
            return "running"
        return None


# Singleton
_fuzzer_instance: Optional[DirectoryFuzzer] = None


def get_directory_fuzzer() -> DirectoryFuzzer:
    """Get or create the global DirectoryFuzzer instance."""
    global _fuzzer_instance
    if _fuzzer_instance is None:
        _fuzzer_instance = DirectoryFuzzer()
    return _fuzzer_instance
