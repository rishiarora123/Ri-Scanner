"""
Endpoint Discovery - Phase 2 Enhancement
Multi-stage passive endpoint discovery using robots.txt, sitemap, JS crawling
"""

import httpx
import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Set
from urllib.parse import urljoin
import asyncio

# Common User-Agent to avoid blocking
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

class EndpointDiscovery:
    """Multi-stage endpoint discovery: passive → light active"""
    
    async def discover_all_endpoints(self, domain: str) -> Dict[str, any]:
        """Master discovery function combining all methods"""
        
        all_endpoints = {
            "from_robots_txt": await self.parse_robots_txt(domain),
            "from_sitemap": await self.parse_sitemap_xml(domain),
            "from_javascript": await self.extract_api_from_js(domain),
            "from_common_paths": await self.probe_common_paths(domain),
            "well_known": await self.discover_well_known(domain),
        }
        
        # Flatten and deduplicate
        all_found = set()
        for source, endpoints in all_endpoints.items():
            if isinstance(endpoints, list):
                all_found.update(str(e) for e in endpoints if e)
        
        return {
            "total_endpoints": len(all_found),
            "endpoints_by_source": all_endpoints,
            "all_endpoints": sorted(list(all_found))
        }
    
    async def parse_robots_txt(self, domain: str) -> List[str]:
        """Extract paths from robots.txt"""
        endpoints = []
        
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                response = await client.get(f"https://{domain}/robots.txt")
                
                # Parse Allow/Disallow rules
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Allow:') or line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            endpoints.append(path)
                
                # Also check for Sitemap
                if 'Sitemap:' in response.text:
                    for line in response.text.split('\n'):
                        if line.startswith('Sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            endpoints.append(sitemap_url)
        
        except Exception as e:
            pass
        
        return endpoints
    
    async def parse_sitemap_xml(self, domain: str) -> List[str]:
        """Extract URLs from sitemap.xml"""
        endpoints = []
        
        sitemap_urls = [
            f"https://{domain}/sitemap.xml",
            f"https://{domain}/sitemap_index.xml",
            f"https://{domain}/sitemap1.xml",
            f"https://{domain}/sitemap-index.xml"
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                    response = await client.get(sitemap_url)
                    
                    if response.status_code == 200:
                        root = ET.fromstring(response.content)
                        
                        # Extract <loc> elements
                        for loc in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                            url = loc.text
                            if url:
                                # Extract path from URL
                                path = url.replace(f"https://{domain}", "").replace(f"http://{domain}", "")
                                if path:
                                    endpoints.append(path)
            
            except Exception:
                continue
        
        return endpoints
    
    async def extract_api_from_js(self, domain: str) -> List[str]:
        """Extract API endpoints from JavaScript files"""
        api_endpoints = []
        
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, headers=DEFAULT_HEADERS) as client:
                response = await client.get(f"https://{domain}")
                html = response.text
            
            # Find all script sources
            script_urls = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html)
            
            for script_url in script_urls[:5]:  # Limit to first 5 scripts
                # Make absolute URL
                full_url = urljoin(f"https://{domain}", script_url)
                
                try:
                    async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                        js_response = await client.get(full_url)
                        js_code = js_response.text[:50000]  # Limit to 50KB
                        
                        # Look for API patterns
                        patterns = [
                            r'["\']\/api\/[a-zA-Z0-9/_\-\.]*["\']',
                            r'["\']\/rest\/[a-zA-Z0-9/_\-\.]*["\']',
                            r'["\']\/v\d+\/[a-zA-Z0-9/_\-\.]*["\']',
                            r'["\']\/graphql["\']',
                            r'fetch\(["\']([^"\']+)["\']',
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, js_code)
                            api_endpoints.extend(matches)
                
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return list(set(api_endpoints))  # Deduplicate
    
    async def probe_common_paths(self, domain: str) -> List[Dict]:
        """Light fuzzing of common endpoints (SAFE wordlist only)"""
        found_endpoints = []
        
        common_paths = [
            "/api/",
            "/api/v1/",
            "/api/v2/",
            "/rest/",
            "/graphql",
            "/admin/",
            "/admin-panel/",
            "/dashboard/",
            "/.well-known/",
            "/.git/",
            "/sitemap.xml",
            "/robots.txt",
        ]
        
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                for path in common_paths:
                    try:
                        response = await client.head(
                            f"https://{domain}{path}",
                            follow_redirects=False,
                            timeout=3
                        )
                        
                        # 200, 301, 302, 403 = endpoint exists
                        if response.status_code in [200, 301, 302, 403]:
                            found_endpoints.append({
                                "path": path,
                                "status": response.status_code,
                                "exists": True
                            })
                    
                    except Exception:
                        continue
        
        except Exception:
            pass
        
        return found_endpoints
    
    async def discover_well_known(self, domain: str) -> List[str]:
        """Discover .well-known endpoints (ACME, OAuth, etc.)"""
        found = []
        
        well_known_paths = [
            "/.well-known/acme-challenge/",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/security.txt",
        ]
        
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                for path in well_known_paths:
                    try:
                        response = await client.get(f"https://{domain}{path}", timeout=3)
                        if response.status_code in [200, 403]:
                            found.append(path)
                    except:
                        continue
        except:
            pass
        
        return found
