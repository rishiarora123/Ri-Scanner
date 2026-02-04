"""
HTTP Request Helper Module

Provides optimized HTTP probing with technology/WAF detection.
Includes favicon hashing and JARM fingerprinting integration.
"""
import asyncio
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Set
from bs4 import BeautifulSoup, SoupStrainer
import aiohttp
import mmh3
import codecs

from .utils import is_valid_domain, log_to_server
from .jarm_helper import get_jarm_hash


# Pre-compiled strainer for HTML parsing (reuse for performance)
_HTML_STRAINER = SoupStrainer(["title", "body"])

# Technology detection signatures
TECH_SIGNATURES = {
    "header": {
        "PHP": ["PHP"],
        "ASP.NET": ["ASP.NET"],
        "Express.js": ["Express"],
        "Nginx": ["nginx"],
        "Apache": ["apache"],
        "Cloudflare CDN": ["cloudflare"],
        "IIS": ["microsoft-iis"],
    },
    "body": {
        "WordPress": ["wordpress", "wp-content"],
        "React": ["react", "_reactroot"],
        "Vue.js": ["vue", "__vue__"],
        "Bootstrap": ["bootstrap"],
        "jQuery": ["jquery"],
        "Angular": ["ng-app", "angular"],
    }
}

# WAF detection signatures
WAF_SIGNATURES = [
    ("cloudflare", "cookie:__cfduid", "Cloudflare"),
    ("cloudflare", "server:cloudflare", "Cloudflare"),
    ("awselb", "server:awselb", "AWS ELB"),
    ("cloudfront", "via:cloudfront", "AWS CloudFront"),
    ("akamai", "server:akamai", "Akamai"),
    ("akamai", "via:akamai", "Akamai"),
    ("incapsula", "cookie:incap_ses", "Imperva Incapsula"),
    ("sucuri", "server:sucuri", "Sucuri"),
]


async def get_favicon_hash(
    session: aiohttp.ClientSession, 
    base_url: str, 
    timeout: int = 5
) -> Optional[int]:
    """
    Fetch and hash the favicon.ico file.
    
    Args:
        session: aiohttp session for requests
        base_url: Base URL of the target
        timeout: Request timeout in seconds
        
    Returns:
        MMH3 hash of the favicon or None if not found
    """
    try:
        favicon_url = f"{base_url.rstrip('/')}/favicon.ico"
        async with session.get(
            favicon_url, 
            timeout=aiohttp.ClientTimeout(total=timeout), 
            ssl=False
        ) as resp:
            if resp.status == 200:
                favicon = await resp.read()
                if len(favicon) > 0:
                    return mmh3.hash(codecs.encode(favicon, "base64"))
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return None


def _detect_technologies(headers: Dict[str, str], body_text: str) -> Set[str]:
    """Detect technologies from response headers and body."""
    technologies = set()
    
    # Check headers
    server = headers.get("Server", "").lower()
    powered_by = headers.get("X-Powered-By", "")
    
    for tech, signatures in TECH_SIGNATURES["header"].items():
        for sig in signatures:
            if sig.lower() in server or sig in powered_by:
                technologies.add(tech)
                break
    
    # Check body
    body_lower = body_text.lower()
    for tech, signatures in TECH_SIGNATURES["body"].items():
        for sig in signatures:
            if sig in body_lower:
                technologies.add(tech)
                break
    
    return technologies


def _detect_waf(headers: Dict[str, str], cookies: str) -> Optional[str]:
    """Detect WAF from response headers and cookies."""
    server = headers.get("Server", "").lower()
    via = headers.get("Via", "").lower()
    
    for keyword, check, waf_name in WAF_SIGNATURES:
        check_type, check_val = check.split(":", 1)
        if check_type == "server" and check_val in server:
            return waf_name
        elif check_type == "via" and check_val in via:
            return waf_name
        elif check_type == "cookie" and check_val in cookies.lower():
            return waf_name
    
    return None


async def _parse_response(
    session: aiohttp.ClientSession,
    url: str,
    port: int,
    protocol: str,
    ip: str,
    common_name: str,
    make_request_by_ip: bool,
    config
) -> Optional[Dict[str, Any]]:
    """
    Parse HTTP response and extract metadata.
    
    Returns structured data including title, headers, tech stack, etc.
    """
    try:
        async with session.get(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=config.timeout),
            ssl=False
        ) as res:
            response = await res.text(encoding="utf-8", errors="replace")
            content_type = res.headers.get("Content-Type", "")
            
            # Extract headers
            response_headers = {
                k: v.encode("utf-8", "surrogatepass").decode("utf-8")
                for k, v in res.headers.items()
            }
            
            # Get redirect info
            redirected_domain = str(res.url) if res.history else ""
            cookies = res.headers.get("Set-Cookie", "")
            
            # Parse content based on type
            title = ""
            first_300_words = ""
            
            if "html" in content_type.lower():
                soup = BeautifulSoup(response, "html.parser", parse_only=_HTML_STRAINER)
                
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()
                
                if soup.body:
                    body_text = soup.body.get_text(separator=" ", strip=True)
                    words = body_text.split()
                    first_300_words = " ".join(words[:300])
                elif not soup.title:
                    # Fallback for dynamic content
                    words = response.split()
                    first_300_words = " ".join(words[:300])
                    
            elif "xml" in content_type.lower():
                try:
                    root = ET.fromstring(response)
                    words = []
                    for elem in root.iter():
                        if elem.text:
                            words.extend(elem.text.split())
                            if len(words) >= 300:
                                break
                    first_300_words = " ".join(words[:300])
                except ET.ParseError:
                    pass
                    
            elif "json" in content_type.lower():
                first_300_words = response[:1000]
                
            elif "plain" in content_type.lower():
                words = response.split()
                first_300_words = " ".join(words[:300])
            
            # Detect technologies and WAF
            technologies = _detect_technologies(response_headers, response)
            waf = _detect_waf(response_headers, cookies)
            
            # Get favicon hash (non-blocking)
            fav_hash = await get_favicon_hash(
                session, 
                f"{protocol}{ip if make_request_by_ip else common_name}:{port}",
                config.timeout
            )
            
            # Get JARM hash (only for HTTPS/443)
            jarm_hash = None
            if str(port) == "443" or protocol == "https://":
                jarm_hash = await asyncio.to_thread(get_jarm_hash, ip, int(port))
            
            return {
                "title": title.encode("utf-8", "surrogatepass").decode("utf-8"),
                "request": f"{protocol}{ip if make_request_by_ip else common_name}:{port}",
                "redirected_url": redirected_domain,
                "ip": ip,
                "port": str(port),
                "domain": common_name,
                "response_text": first_300_words,
                "response_headers": response_headers,
                "favicon_hash": fav_hash,
                "jarm_hash": jarm_hash,
                "technologies": list(technologies),
                "waf": waf
            }
            
    except ET.ParseError as e:
        log_to_server(f"XML Parse Error for {url}: {e}")
    except asyncio.TimeoutError:
        pass  # Timeout is expected, silent
    except aiohttp.ClientError:
        pass  # Connection errors are expected
    except Exception as e:
        log_to_server(f"HTTP Error for {url}: {e}")
    
    return None


async def make_get_request(
    session: aiohttp.ClientSession,
    protocol: str,
    ip: str,
    common_name: str,
    config,
    make_request_by_ip: bool = True
) -> Optional[Any]:
    """
    Make HTTP/HTTPS GET request and parse response.
    
    Args:
        session: aiohttp session
        protocol: "http://" or "https://"
        ip: Target IP address
        common_name: Domain from SSL cert
        config: ScannerConfig object
        make_request_by_ip: Whether to request by IP or domain
        
    Returns:
        Parsed response data or None
    """
    if make_request_by_ip:
        if protocol == "http://":
            results = []
            for port in config.ports:
                url = f"{protocol}{ip}:{port}"
                result = await _parse_response(
                    session, url, port, protocol, ip, 
                    common_name, make_request_by_ip, config
                )
                if result:
                    results.append(result)
            return results if results else None
        else:
            url = f"{protocol}{ip}:{config.ssl_port}"
            return await _parse_response(
                session, url, config.ssl_port, protocol, ip,
                common_name, make_request_by_ip, config
            )
    else:
        port = 80 if protocol == "http://" else config.ssl_port
        url = f"{protocol}{common_name}:{port}"
        return await _parse_response(
            session, url, port, protocol, ip,
            common_name, make_request_by_ip, config
        )


async def check_site(
    session: aiohttp.ClientSession,
    ip: str,
    common_name: str,
    config
) -> Optional[Dict[str, Any]]:
    """
    Check a site by IP with optional domain probing.
    
    Makes requests via IP and domain name to gather complete data.
    
    Args:
        session: aiohttp session
        ip: Target IP address
        common_name: Domain from SSL certificate
        config: ScannerConfig object
        
    Returns:
        Dictionary with all response data or None
    """
    try:
        temp_dict = {}
        
        # Normalize common_name - handle None and empty strings
        common_name = (common_name or "").strip()
        
        # If wildcard, empty, or invalid domain, only probe by IP
        if not common_name or "*" in common_name or not is_valid_domain(common_name):
            for protocol in config.protocols:
                result = await make_get_request(
                    session, protocol, ip, common_name, config, True
                )
                key = f'{protocol.replace("://", "")}_responseForIP'
                temp_dict[key] = result
        else:
            # Probe by domain name
            for protocol in config.protocols:
                result = await make_get_request(
                    session, protocol, ip, common_name, config, False
                )
                key = f'{protocol.replace("://", "")}_responseForDomainName'
                temp_dict[key] = result
            
            # Also probe by IP
            for protocol in config.protocols:
                result = await make_get_request(
                    session, protocol, ip, common_name, config, True
                )
                key = f'{protocol.replace("://", "")}_responseForIP'
                temp_dict[key] = result
        
        # Filter None values
        temp_dict = {k: v for k, v in temp_dict.items() if v is not None}
        return temp_dict if temp_dict else None
        
    except Exception as e:
        log_to_server(f"Critical Error for {ip}: {e}")
    
    return None