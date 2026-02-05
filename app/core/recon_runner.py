"""
Ri-Scanner Pro - Recon Runner

Handles the execution of reconnaissance tools including:
- CLI tool execution (Subfinder, Amass, etc.)
- API integrations (crt.sh, Shodan, Censys, ZoomEye, FOFA, etc.)
- Result collection and aggregation
- Caching and rate limiting
"""
import os
import subprocess
import asyncio
import aiohttp
import json
import time
import base64
import hashlib
from typing import Dict, List, Optional, Any, Set
from concurrent.futures import ThreadPoolExecutor
from .tools_config import TOOLS, Tool, get_tools_by_category
from .tools_checker import get_tools_checker
from .utils import log_to_server


def log_event(message):
    """Log to the server UI."""
    print(message)
    log_to_server(message)


class ResultCache:
    """Simple in-memory cache for API results with TTL."""
    
    def __init__(self, ttl_seconds: int = 3600):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._ttl = ttl_seconds
    
    def _make_key(self, tool_id: str, target: str) -> str:
        return hashlib.md5(f"{tool_id}:{target}".encode()).hexdigest()
    
    def get(self, tool_id: str, target: str) -> Optional[List[str]]:
        key = self._make_key(tool_id, target)
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["timestamp"] < self._ttl:
                return entry["data"]
            else:
                del self._cache[key]
        return None
    
    def set(self, tool_id: str, target: str, data: List[str]):
        key = self._make_key(tool_id, target)
        self._cache[key] = {"data": data, "timestamp": time.time()}
    
    def clear(self):
        self._cache.clear()


class ReconRunner:
    """
    Executes reconnaissance tools and collects results.
    Features: API integrations, caching, rate limiting.
    """
    
    def __init__(self):
        self.checker = get_tools_checker()
        self.results: Dict[str, List[str]] = {}
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._cache = ResultCache(ttl_seconds=3600)
        self._api_semaphore = asyncio.Semaphore(5)
    
    async def run_subdomain_recon(self, domain: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run subdomain enumeration using multiple tools.
        """
        results = {
            "domain": domain,
            "subdomains": set(),
            "tool_results": {},
            "errors": [],
            "cached_tools": []
        }
        
        # Get available tools
        if tools is None:
            tools = self._get_available_recon_tools()
        
        log_event(f"[*] Running {len(tools)} tools for subdomain recon: {', '.join(tools)}")
        
        # Run tools concurrently with rate limiting
        tasks = []
        for tool_id in tools:
            task = self._run_tool_with_cache(tool_id, domain)
            tasks.append(task)
        
        tool_outputs = await asyncio.gather(*tasks, return_exceptions=True)
        
        for tool_id, output in zip(tools, tool_outputs):
            if isinstance(output, Exception):
                log_event(f"[!] {tool_id}: Error - {str(output)}")
                results["errors"].append({"tool": tool_id, "error": str(output)})
            elif isinstance(output, dict):
                data = output.get("data", [])
                cached = output.get("cached", False)
                count = len(data) if isinstance(data, list) else 0
                
                log_event(f"[+] {tool_id}: Found {count} subdomains" + (" (cached)" if cached else ""))
                results["tool_results"][tool_id] = data
                if cached:
                    results["cached_tools"].append(tool_id)
                if isinstance(data, list):
                    results["subdomains"].update(data)
                    # Real-time save
                    try:
                        from .subdomain_manager import get_subdomain_manager
                        manager = get_subdomain_manager()
                        manager.save_subdomains(domain, data, source=tool_id)
                    except Exception as e:
                        print(f"Incremental save error: {e}")
            else:
                count = len(output) if isinstance(output, list) else 0
                log_event(f"[+] {tool_id}: Found {count} subdomains")
                results["tool_results"][tool_id] = output
                if isinstance(output, list):
                    results["subdomains"].update(output)
                    # Real-time save
                    try:
                        from .subdomain_manager import get_subdomain_manager
                        manager = get_subdomain_manager()
                        manager.save_subdomains(domain, output, source=tool_id)
                    except Exception as e:
                        print(f"Incremental save error: {e}")
        
        results["subdomains"] = sorted(list(results["subdomains"]))
        results["total"] = len(results["subdomains"])
        log_event(f"[*] Total unique subdomains from all tools: {results['total']}")
        
        return results
    
    def _get_available_recon_tools(self) -> List[str]:
        """
        Get list of available tools.
        - ALL API-only tools are included (no CLI needed)
        - CLI tools only if they are installed
        """
        available = []
        grouped = get_tools_by_category()
        
        # Categories to scan for subdomains
        categories = ["subdomain", "cert", "search_engine"]
        
        for category in categories:
            if category not in grouped:
                continue
                
            for tool in grouped[category]:
                # API-only tools are always available
                if tool.is_api_only:
                    # Check if API key is configured (if required)
                    if tool.requires_api:
                        api_ok, _ = self.checker.check_api_keys(tool)
                        if api_ok:
                            available.append(tool.id)
                    else:
                        available.append(tool.id)
                else:
                    # CLI tools need to be installed
                    is_installed, _ = self.checker.check_tool_installed(tool)
                    if is_installed:
                        available.append(tool.id)
        
        return available
    
    async def _run_tool_with_cache(self, tool_id: str, target: str) -> Dict[str, Any]:
        """Run tool with caching and rate limiting."""
        cached = self._cache.get(tool_id, target)
        if cached is not None:
            return {"data": cached, "cached": True}
        
        tool = TOOLS.get(tool_id)
        if tool and tool.is_api_only:
            async with self._api_semaphore:
                result = await self._run_tool(tool_id, target)
        else:
            result = await self._run_tool(tool_id, target)
        
        if isinstance(result, list) and len(result) > 0:
            self._cache.set(tool_id, target, result)
        
        return {"data": result, "cached": False}
    
    async def _run_tool(self, tool_id: str, target: str) -> List[str]:
        """Run a specific tool and return results."""
        tool = TOOLS.get(tool_id)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_id}")
        
        if tool.is_api_only:
            return await self._run_api_tool(tool, target)
        else:
            return await self._run_cli_tool(tool, target)
    
    async def _run_cli_tool(self, tool: Tool, target: str) -> List[str]:
        """Execute a CLI tool and parse output."""
        if not tool.usage_template:
            return []
        
        cmd = tool.usage_template.format(domain=target, ip=target, url=target, target=target)
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            
            output = stdout.decode('utf-8', errors='ignore')
            lines = [line.strip() for line in output.split('\n') if line.strip()]
            
            return [line for line in lines if self._is_valid_subdomain(line, target)]
            
        except asyncio.TimeoutError:
            return []
        except Exception as e:
            raise Exception(f"{tool.name} error: {str(e)}")
    
    async def _run_api_tool(self, tool: Tool, target: str) -> List[str]:
        """Execute an API-based tool."""
        handlers = {
            "crtsh": self._api_crtsh,
            "certspotter": self._api_certspotter,
            "bufferover": self._api_bufferover,
            "securitytrails": self._api_securitytrails,
            "shodan": self._api_shodan,
            "zoomeye": self._api_zoomeye,
            "fofa": self._api_fofa,
        }
        
        handler = handlers.get(tool.id)
        if handler:
            return await handler(target)
        return []
    
    # ==================== API INTEGRATIONS ====================
    
    async def _api_crtsh(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency logs."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        try:
                            data = json.loads(text)
                            for entry in data:
                                name = entry.get("name_value", "")
                                for n in name.split('\n'):
                                    n = n.strip().lower()
                                    if n.startswith('*.'):
                                        n = n[2:]
                                    if n.endswith(domain):
                                        subdomains.add(n)
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            log_event(f"[!] crt.sh error: {e}")
        
        return list(subdomains)
    
    async def _api_certspotter(self, domain: str) -> List[str]:
        """Query Certspotter for certificate issuances."""
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            for name in entry.get("dns_names", []):
                                name = name.lower()
                                if name.startswith('*.'):
                                    name = name[2:]
                                if name.endswith(domain):
                                    subdomains.add(name)
        except Exception as e:
            log_event(f"[!] Certspotter error: {e}")
        
        return list(subdomains)
    
    async def _api_bufferover(self, domain: str) -> List[str]:
        """Query Bufferover for DNS data."""
        subdomains = set()
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for record in data.get("FDNS_A", []) or []:
                            if "," in record:
                                parts = record.split(",")
                                if len(parts) >= 2:
                                    name = parts[1].lower()
                                    if name.endswith(domain):
                                        subdomains.add(name)
        except Exception as e:
            log_event(f"[!] Bufferover error: {e}")
        
        return list(subdomains)
    
    async def _api_securitytrails(self, domain: str) -> List[str]:
        """Query SecurityTrails API (requires API key)."""
        settings = self.checker.get_settings()
        api_key = settings.get("SECURITYTRAILS_KEY")
        
        if not api_key:
            return []
        
        subdomains = set()
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"APIKEY": api_key}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get("subdomains", []):
                            subdomains.add(f"{sub}.{domain}")
        except Exception as e:
            log_event(f"[!] SecurityTrails error: {e}")
        
        return list(subdomains)
    
    async def _api_shodan(self, domain: str) -> List[str]:
        """Query Shodan API (requires API key)."""
        settings = self.checker.get_settings()
        api_key = settings.get("SHODAN_API_KEY")
        
        if not api_key:
            return []
        
        subdomains = set()
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get("subdomains", []):
                            subdomains.add(f"{sub}.{domain}")
        except Exception as e:
            log_event(f"[!] Shodan error: {e}")
        
        return list(subdomains)
    

    async def _api_zoomeye(self, domain: str) -> List[str]:
        """Query ZoomEye API (requires API key)."""
        settings = self.checker.get_settings()
        api_key = settings.get("ZOOMEYE_API_KEY")
        
        if not api_key:
            return []
        
        subdomains = set()
        url = f"https://api.zoomeye.org/domain/search?q={domain}&type=1"
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"API-KEY": api_key}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("list", []):
                            name = item.get("name", "").lower()
                            if name.endswith(domain):
                                subdomains.add(name)
        except Exception as e:
            log_event(f"[!] ZoomEye error: {e}")
        
        return list(subdomains)
    
    async def _api_fofa(self, domain: str) -> List[str]:
        """Query FOFA API (requires API key)."""
        settings = self.checker.get_settings()
        email = settings.get("FOFA_EMAIL")
        api_key = settings.get("FOFA_KEY")
        
        if not email or not api_key:
            return []
        
        subdomains = set()
        query = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={email}&key={api_key}&qbase64={query}&size=100"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for result in data.get("results", []):
                            if len(result) >= 1:
                                host = result[0].lower()
                                if host.startswith("http"):
                                    from urllib.parse import urlparse
                                    host = urlparse(host).netloc
                                if host.endswith(domain):
                                    subdomains.add(host)
        except Exception as e:
            log_event(f"[!] FOFA error: {e}")
        
        return list(subdomains)
    
    def _is_valid_subdomain(self, line: str, domain: str) -> bool:
        """Check if a line looks like a valid subdomain."""
        line = line.lower().strip()
        
        if not line.endswith(domain):
            return False
        
        if ' ' in line or '\t' in line:
            return False
        
        if any(c in line for c in ['/', ':', 'http']):
            return False
        
        return True
    
    def clear_cache(self):
        """Clear the result cache."""
        self._cache.clear()


# Singleton instance
_runner_instance: Optional[ReconRunner] = None


def get_recon_runner() -> ReconRunner:
    """Get or create the global ReconRunner instance."""
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = ReconRunner()
    return _runner_instance
