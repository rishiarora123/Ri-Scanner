"""
Crawler Helper - Web crawler using Katana
"""
import subprocess
import asyncio
import json
import os
from typing import List, Dict, Optional


class CrawlerHelper:
    """Web crawler using Katana tool."""
    
    def __init__(self, base_dir: str = "Data/subdomains"):
        self.base_dir = base_dir
    
    async def run_katana(self, url: str, depth: int = 3, timeout: int = 60) -> Dict:
        """
        Run Katana crawler on a URL.
        
        Args:
            url: Target URL
            depth: Crawl depth
            timeout: Timeout in seconds
            
        Returns:
            Dict with urls, forms, endpoints
        """
        result = {
            "url": url,
            "urls": [],
            "forms": [],
            "endpoints": [],
            "error": None
        }
        
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # Run Katana
            cmd = [
                "katana",
                "-u", url,
                "-d", str(depth),
                "-jc",  # JavaScript crawling
                "-silent",
                "-jsonl"  # JSON lines output
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            if stdout:
                # Parse JSON lines
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            result["urls"].append(data.get("url", ""))
                            
                            # Extract forms
                            if data.get("form"):
                                result["forms"].append(data["form"])
                            
                            # Extract endpoints (API-like paths)
                            url_path = data.get("url", "")
                            if any(ext in url_path for ext in ['/api/', '/v1/', '/v2/', '.json', '.xml']):
                                result["endpoints"].append(url_path)
                        except json.JSONDecodeError:
                            # Plain URL output
                            result["urls"].append(line.strip())
            
            # Deduplicate
            result["urls"] = list(set(result["urls"]))
            result["endpoints"] = list(set(result["endpoints"]))
            
        except asyncio.TimeoutError:
            result["error"] = "Crawler timeout"
        except FileNotFoundError:
            result["error"] = "Katana not installed"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def save_crawler_results(self, scan_id: str, domain: str, results: Dict) -> bool:
        """Save crawler results to file."""
        try:
            scan_dir = os.path.join(self.base_dir, scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            
            file_path = os.path.join(scan_dir, "crawler_results.json")
            
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
            print(f"Error saving crawler results: {e}")
            return False
    
    def get_crawler_results(self, scan_id: str, domain: str) -> Optional[Dict]:
        """Get crawler results for a domain."""
        try:
            file_path = os.path.join(self.base_dir, scan_id, "crawler_results.json")
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            return data.get(domain)
        except Exception as e:
            print(f"Error getting crawler results: {e}")
            return None


# Singleton
_crawler_instance: Optional[CrawlerHelper] = None


def get_crawler_helper() -> CrawlerHelper:
    """Get or create the global CrawlerHelper instance."""
    global _crawler_instance
    if _crawler_instance is None:
        _crawler_instance = CrawlerHelper()
    return _crawler_instance
