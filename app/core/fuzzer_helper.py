import asyncio
import aiohttp
import time
from typing import List, Dict, Any, Optional
import os

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
            # Default to http for IPs/raw hostnames if scheme missing
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
            # Includes gaierror, InvalidURL, etc.
            pass
        except Exception:
            pass
        return None

    async def fuzz_target(self, target: str, paths: List[str], progress_callback=None):
        """Fuzzes a single target against the wordlist."""
        target_url = self._normalize_url(target)
        semaphore = asyncio.Semaphore(self.concurrency)
        
        # Use a connector to limit total connections and prevent DNS overload
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
