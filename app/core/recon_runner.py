"""
Ri-Scanner Pro - Simplified Recon Runner
"""
import os
import asyncio
import subprocess
from typing import Dict, List, Optional, Any, Set
from .tools_config import TOOLS, Tool
def log_event(message):
    print(message)

class ReconRunner:
    """Executes specifically requested subdomain discovery tools."""
    
    def __init__(self):
        self._api_semaphore = asyncio.Semaphore(5)
    
    async def run_subdomain_recon(self, domain: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run subdomain enumeration using chaos, subfinder, and assetfinder."""
        if tools is None:
            tools = ["chaos", "subfinder", "assetfinder"]
        
        log_event(f"[*] Starting Subdomain Discovery on {domain} using {', '.join(tools)}")
        
        results = {
            "domain": domain,
            "subdomains": set(),
            "tool_results": {}
        }
        
        tasks = []
        for tool_id in tools:
            if tool_id in TOOLS:
                tasks.append(self._run_tool(tool_id, domain))
        
        tool_outputs = await asyncio.gather(*tasks, return_exceptions=True)
        
        for tool_id, output in zip(tools, tool_outputs):
            if isinstance(output, Exception):
                log_event(f"[!] {tool_id} error: {str(output)}")
                continue
            
            count = len(output)
            log_event(f"[+] {tool_id} found {count} subdomains")
            results["tool_results"][tool_id] = output
            results["subdomains"].update(output)
            
            # Incremental save to MongoDB via SubdomainManager
            try:
                from .subdomain_manager import get_subdomain_manager
                manager = get_subdomain_manager()
                manager.save_subdomains(scan_id=domain, subdomains=output, source=tool_id)
            except Exception as e:
                print(f"Error saving results for {tool_id}: {e}")
        
        results["subdomains"] = sorted(list(results["subdomains"]))
        log_event(f"[*] Total unique subdomains found: {len(results['subdomains'])}")
        return results

    async def _run_tool(self, tool_id: str, target: str) -> List[str]:
        tool = TOOLS.get(tool_id)
        if not tool or not tool.usage_template:
            return []
        
        # Handle API keys for Chaos if needed
        env = os.environ.copy()
        if tool.requires_api:
            # Assume keys are already in environment
            pass

        cmd = tool.usage_template.format(domain=target, target=target)
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            
            output = stdout.decode('utf-8', errors='ignore')
            lines = [line.strip().lower() for line in output.split('\n') if line.strip()]
            
            # Basic validation: must end with domain and not contain spaces
            valid_subs = [l for l in lines if l.endswith(target) and ' ' not in l and '/' not in l]
            return list(set(valid_subs))
            
        except Exception as e:
            raise Exception(f"{tool_id} execution failed: {str(e)}")

_runner_instance: Optional[ReconRunner] = None

def get_recon_runner() -> ReconRunner:
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = ReconRunner()
    return _runner_instance
