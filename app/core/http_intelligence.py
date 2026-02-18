"""
HTTP Intelligence Collection - Phase 2 Enhancement
Collects comprehensive HTTP headers, security info, and tech indicators
"""

import httpx
import asyncio
from typing import Dict, Any, List
from datetime import datetime
from bs4 import BeautifulSoup

# Common User-Agent to avoid blocking
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

class HTTPIntelligence:
    """Collect comprehensive HTTP headers and metadata"""
    
    def __init__(self):
        self.timeout = 10
        self.common_ports = [80, 443, 8080, 8443, 3000, 5000]
    
    async def fetch_headers_comprehensive(self, domain: str) -> Dict[str, Any]:
        """
        Attempt HTTP(S) requests on common ports and extract all headers.
        Returns structured data on first successful response.
        """
        headers_result = {
            "primary_endpoint": None,
            "status_code": None,
            "headers_raw": {},
            "security_headers": {},
            "tech_indicators": {},
            "redirect_chain": [],
            "cookies": [],
            "cache_control": None,
            "server_info": None,
            "response_time": None,
            "page_text": ""
        }
        
        # Try both HTTP and HTTPS
        for protocol in ['https', 'http']:  # HTTPS first (more secure)
            for port in self.common_ports:
                endpoint = f"{protocol}://{domain}:{port}"
                
                try:
                    async with httpx.AsyncClient(
                        timeout=self.timeout,
                        follow_redirects=True,
                        verify=False,  # Self-signed cert handling
                        headers=DEFAULT_HEADERS
                    ) as client:
                        import time
                        start = time.time()
                        response = await client.get(endpoint)
                        response_time = time.time() - start
                        
                        # Success - extract all data
                        headers_result["primary_endpoint"] = endpoint
                        headers_result["status_code"] = response.status_code
                        headers_result["headers_raw"] = dict(response.headers)
                        headers_result["response_time"] = response_time
                        
                        # Extract security headers
                        headers_result["security_headers"] = {
                            "x_frame_options": response.headers.get("X-Frame-Options"),
                            "x_content_type_options": response.headers.get("X-Content-Type-Options"),
                            "content_security_policy": response.headers.get("Content-Security-Policy"),
                            "strict_transport_security": response.headers.get("Strict-Transport-Security"),
                            "x_xss_protection": response.headers.get("X-XSS-Protection"),
                            "access_control_allow_origin": response.headers.get("Access-Control-Allow-Origin"),
                        }
                        
                        # Extract tech indicators
                        headers_result["tech_indicators"] = {
                            "server": response.headers.get("Server"),
                            "x_powered_by": response.headers.get("X-Powered-By"),
                            "x_aspnet_version": response.headers.get("X-AspNet-Version"),
                            "x_runtime": response.headers.get("X-Runtime"),
                            "etag": response.headers.get("ETag"),
                            "via": response.headers.get("Via"),  # Proxy info
                        }
                        
                        # Extract cookies
                        if "set-cookie" in response.headers:
                            cookies = []
                            for cookie_header in response.headers.get_list("Set-Cookie"):
                                cookies.append(cookie_header.split(';')[0])
                            headers_result["cookies"] = cookies
                        
                        # Cache control
                        headers_result["cache_control"] = response.headers.get("Cache-Control")
                        
                        # Redirect chain (if any)
                        if response.history:
                            headers_result["redirect_chain"] = [
                                {
                                    "from": str(h.url),
                                    "status": h.status_code,
                                    "to": str(response.history[i+1].url) if i+1 < len(response.history) else str(response.url)
                                }
                                for i, h in enumerate(response.history)
                            ]
                        
                        # Capture and clean page text
                        try:
                            soup = BeautifulSoup(response.text, "html.parser")
                            # Remove script and style elements
                            for script_or_style in soup(["script", "style"]):
                                script_or_style.decompose()
                            # Get text
                            text = soup.get_text(separator=" ")
                            # Clean up whitespace
                            lines = (line.strip() for line in text.splitlines())
                            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                            clean_text = " ".join(chunk for chunk in chunks if chunk)
                            headers_result["page_text"] = clean_text[:5000] # Cap at 5k chars for DB sanity
                        except Exception as e:
                            headers_result["page_text"] = f"Error capturing text: {str(e)}"
                        
                        return headers_result
                        
                except asyncio.TimeoutError:
                    continue
                except (httpx.ConnectError, httpx.ConnectTimeout):
                    continue
                except Exception as e:
                    # Log failure and continue to next protocol/port
                    continue
        
        # No successful connection
        return headers_result
    
    async def analyze_headers_for_tech(self, headers: Dict[str, Any]) -> List[str]:
        """Extract technology hints from headers"""
        detected_tech = []
        
        server_header = headers.get("tech_indicators", {}).get("server", "")
        if server_header:
            # Apache/2.4.41 (Ubuntu)
            # nginx/1.18.0
            # Microsoft-IIS/10.0
            if "apache" in server_header.lower():
                detected_tech.append("Apache")
            if "nginx" in server_header.lower():
                detected_tech.append("Nginx")
            if "iis" in server_header.lower():
                detected_tech.append("Microsoft IIS")
            if "cloudflare" in server_header.lower():
                detected_tech.append("Cloudflare")
            if "litespeed" in server_header.lower():
                detected_tech.append("LiteSpeed")
        
        powered_by = headers.get("tech_indicators", {}).get("x_powered_by", "")
        if powered_by:
            detected_tech.append(powered_by)
        
        aspnet = headers.get("tech_indicators", {}).get("x_aspnet_version", "")
        if aspnet:
            detected_tech.append(f"ASP.NET {aspnet}")
        
        return list(set(detected_tech))  # Remove duplicates
    
    async def check_security_headers(self, headers: Dict[str, Any]) -> Dict[str, bool]:
        """Check for important security headers"""
        security_status = {
            "has_x_frame_options": bool(headers.get("security_headers", {}).get("x_frame_options")),
            "has_x_content_type_options": bool(headers.get("security_headers", {}).get("x_content_type_options")),
            "has_csp": bool(headers.get("security_headers", {}).get("content_security_policy")),
            "has_hsts": bool(headers.get("security_headers", {}).get("strict_transport_security")),
            "has_x_xss_protection": bool(headers.get("security_headers", {}).get("x_xss_protection")),
            "has_cors": bool(headers.get("security_headers", {}).get("access_control_allow_origin")),
        }
        
        return security_status
