"""
Ri-Scanner Pro - Recon Runner

Handles the execution of reconnaissance tools including:
- CLI tool execution
- API integrations (crt.sh, Shodan, Censys, etc.)
- Result collection and aggregation
"""
import os
import subprocess
import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any, Set
from concurrent.futures import ThreadPoolExecutor
from .tools_config import TOOLS, Tool, get_tools_by_category
from .tools_checker import get_tools_checker


class ReconRunner:
    """
    Executes reconnaissance tools and collects results.
    """
    
    def __init__(self):
        self.checker = get_tools_checker()
        self.results: Dict[str, List[str]] = {}  # tool_id -> [subdomains/results]
        self._executor = ThreadPoolExecutor(max_workers=10)
    
    async def run_subdomain_recon(self, domain: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run subdomain enumeration using multiple tools.
        
        Args:
            domain: Target domain
            tools: List of tool IDs to use (None = all available)
            
        Returns:
            Dictionary with results and summary
        """
        results = {
            "domain": domain,
            "subdomains": set(),
            "tool_results": {},
            "errors": []
        }
        
        # Get available tools
        if tools is None:
            tools = self._get_available_subdomain_tools()
        
        # Run tools concurrently
        tasks = []
        for tool_id in tools:
            task = self._run_tool(tool_id, domain)
            tasks.append(task)
        
        tool_outputs = await asyncio.gather(*tasks, return_exceptions=True)
        
        for tool_id, output in zip(tools, tool_outputs):
            if isinstance(output, Exception):
                results["errors"].append({"tool": tool_id, "error": str(output)})
            else:
                results["tool_results"][tool_id] = output
                if isinstance(output, list):
                    results["subdomains"].update(output)
        
        results["subdomains"] = sorted(list(results["subdomains"]))
        results["total"] = len(results["subdomains"])
        
        return results
    
    def _get_available_subdomain_tools(self) -> List[str]:
        """Get list of installed subdomain enumeration tools."""
        available = []
        grouped = get_tools_by_category()
        
        if "subdomain" in grouped:
            for tool in grouped["subdomain"]:
                is_installed, _ = self.checker.check_tool_installed(tool)
                if is_installed:
                    available.append(tool.id)
        
        return available
    
    async def _run_tool(self, tool_id: str, target: str) -> List[str]:
        """Run a specific tool and return results."""
        tool = TOOLS.get(tool_id)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_id}")
        
        # Route to appropriate handler
        if tool.is_api_only:
            return await self._run_api_tool(tool, target)
        else:
            return await self._run_cli_tool(tool, target)
    
    async def _run_cli_tool(self, tool: Tool, target: str) -> List[str]:
        """Execute a CLI tool and parse output."""
        if not tool.usage_template:
            return []
        
        # Build command
        cmd = tool.usage_template.format(domain=target, ip=target, url=target, target=target)
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            
            # Parse output - each line is typically a subdomain
            output = stdout.decode('utf-8', errors='ignore')
            lines = [line.strip() for line in output.split('\n') if line.strip()]
            
            # Filter valid subdomains
            return [line for line in lines if self._is_valid_subdomain(line, target)]
            
        except asyncio.TimeoutExpired:
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
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            # Handle wildcards and multiple names
                            for n in name.split('\n'):
                                n = n.strip().lower()
                                if n.startswith('*.'):
                                    n = n[2:]
                                if n.endswith(domain):
                                    subdomains.add(n)
        except Exception:
            pass
        
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
        except Exception:
            pass
        
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
        except Exception:
            pass
        
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
        except Exception:
            pass
        
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
        except Exception:
            pass
        
        return list(subdomains)
    
    def _is_valid_subdomain(self, line: str, domain: str) -> bool:
        """Check if a line looks like a valid subdomain."""
        line = line.lower().strip()
        
        # Must end with domain
        if not line.endswith(domain):
            return False
        
        # Basic validation
        if ' ' in line or '\t' in line:
            return False
        
        # Check for common non-subdomain patterns
        if any(c in line for c in ['/', ':', 'http']):
            return False
        
        return True


# Singleton instance
_runner_instance: Optional[ReconRunner] = None


def get_recon_runner() -> ReconRunner:
    """Get or create the global ReconRunner instance."""
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = ReconRunner()
    return _runner_instance
