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
from .ssl_helper import parse_certificate


# Pre-compiled strainer for HTML parsing (reuse for performance)
_HTML_STRAINER = SoupStrainer(["title", "body"])

# Technology detection signatures (Comprehensive Stack)
TECH_SIGNATURES = {
    "header": {
        # Backend Languages & Frameworks
        "PHP": ["PHP", "X-PHP-Originating-Script"],
        "ASP.NET": ["ASP.NET", "X-AspNet-Version", "X-Powered-By: ASP.NET"],
        "ASP.NET Core": ["X-Powered-By: ASP.NET Core"],
        "Express.js": ["X-Powered-By: Express"],
        "Django": ["csrftoken", "X-Powered-By: Django"],
        "Flask": ["X-Powered-By: Flask"],
        "FastAPI": ["X-Powered-By: FastAPI"],
        "NestJS": ["X-Powered-By: NestJS"],
        "Ruby on Rails": ["X-Powered-By: Phusion Passenger", "X-Runtime"],
        "Laravel": ["laravel_session", "X-Powered-By: Laravel"],
        "Symfony": ["X-Powered-By: Symfony"],
        "Spring Boot": ["X-Application-Context"],
        "Node.js": ["X-Powered-By: Node.js"],
        
        # Web Servers
        "Nginx": ["nginx"],
        "Apache": ["apache", "Httpd"],
        "LiteSpeed": ["litespeed"],
        "Microsoft IIS": ["microsoft-iis"],
        "Caddy": ["caddy"],
        "Tomcat": ["tomcat"],
        "OpenResty": ["openresty"],
        "Envoy": ["envoy"],
        
        # CDNs & Cache
        "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
        "Akamai": ["akamai", "x-akamai-transformed"],
        "Fastly": ["fastly"],
        "Amazon CloudFront": ["cloudfront", "x-amz-cf-id"],
        "Netlify": ["netlify"],
        "Vercel": ["x-vercel-id", "x-vercel-cache"],
        "Varnish": ["varnish", "x-varnish"],
        "Fastly": ["fastly"],
        
        # Misc
        "Next.js": ["x-nextjs-cache", "x-powered-by: next.js"],
        "Nuxt.js": ["x-nuxt-cache"],
        "Drupal": ["X-Drupal-Cache", "X-Generator: Drupal"],
    },
    "body": {
        # Frontend / UI Frameworks
        "HTML5": ["<!DOCTYPE html>", "<header>", "<footer>", "<article>"],
        "CSS3": ["@media", "flexbox", "grid-template"],
        "Bootstrap": ["bootstrap.css", "bootstrap.min.css", "bootstrap.js", "btn-primary", "col-md-"],
        "Tailwind CSS": ["tailwind", "tw-", "bg-", "text-", "sm:", "md:", "lg:"],
        "Bulma": ["bulma.css", "is-primary", "is-fluid"],
        "Foundation": ["foundation.css", "foundation.js"],
        "Materialize": ["materialize.css", "materialize.js"],
        "React": ["react", "_reactroot", "react-dom", "__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "Angular": ["ng-app", "angular", "_ngcontent", "_nghost", "ng-controller"],
        "Vue.js": ["vue", "__vue__", "vue.js", "v-bind", "v-if"],
        "Svelte": ["svelte-", "svelte.js"],
        "Gatsby": ["gatsby-", "GatsbyImage"],
        "jQuery": ["jquery", "jquery.min.js", "jQuery.fn"],
        "Alpine.js": ["x-data=", "alpine.js", "x-init"],
        "Ember.js": ["Ember.VERSION", "ember-application"],
        "Backbone.js": ["Backbone.VERSION"],
        
        # JS Libraries
        "Lodash": ["lodash", "_.VERSION"],
        "Moment.js": ["moment.js", "moment()."],
        "Axios": ["axios.min.js", "axios.js"],
        "Chart.js": ["chart.js", "new Chart("],
        "D3.js": ["d3.js", "d3.min.js"],
        "Three.js": ["three.js", "three.min.js", "THREE.Scene"],
        "GSAP": ["gsap.js", "TweenMax", "TimelineMax"],
        "RequireJS": ["require.js", "data-main="],
        "Webpack": ["webpack", "__webpack_require__"],
        "Babel": ["babel-polyfill"],
        "Vite": ["/ @vite/client"],
        
        # CMS
        "WordPress": ["wordpress", "wp-content", "wp-includes", "wp-json", "wp-embed"],
        "Joomla": ["joomla", "Joomla!", "option=com_"],
        "Drupal": ["drupal", "sites/all", "Drupal.settings"],
        "Ghost": ["ghost-org", "ghost.io", "ghost-head"],
        "TYPO3": ["typo3"],
        "Magento": ["magento", "Mage.Cookies"],
        "PrestaShop": ["prestashop"],
        "OpenCart": ["opencart"],
        "Shopify": ["shopify", "shopify-checkout", "/cdn.shopify.com/"],
        "BigCommerce": ["bigcommerce"],
        "WooCommerce": ["woocommerce", "wc-ajax"],
        
        # Databases (Indirect)
        "MySQL": ["mysql error", "sql error", "mysql_fetch_array"],
        "PostgreSQL": ["postgresql error", "pg_query"],
        "MongoDB": ["mongodb://", "mongo-db"],
        "Redis": ["redis-", "x-redis"],
        
        # Analytics & Tracking
        "Google Analytics": ["googletagmanager", "google-analytics.com", "UA-", "G-"],
        "Google Tag Manager": ["gtm.js", "googletagmanager.com/gtm.js"],
        "Hotjar": ["hotjar-", "_hjSettings"],
        "Mixpanel": ["mixpanel.init"],
        "Segment": ["analytics.js", "segment.io"],
        "Matomo": ["matomo.js", "piwik.js"],
        "Facebook Pixel": ["facebook.net/en_US/fbevents.js", "fbq("],
        "Adobe Analytics": ["s_code.js", "s_account"],
        "HubSpot": ["hubspot", "hbspt.forms"],
        
        # Security / Auth
        "reCAPTCHA": ["google.com/recaptcha", "g-recaptcha"],
        "hCaptcha": ["hcaptcha.com/1/api.js"],
        "Auth0": ["auth0.min.js", "auth0-js"],
        "Okta": ["okta-sign-in", "okta-auth-js"],
        "Firebase": ["firebase.js", "firebase-app"],
        
        # Payments
        "Stripe": ["js.stripe.com", "stripe-button"],
        "PayPal": ["paypalobjects.com/api/checkout.js", "paypal-button"],
        "Razorpay": ["checkout.razorpay.com"],
        
        # Misc Enterprise
        "Salesforce": ["salesforce.com", "force.com"],
        "SAP": ["sap-ui-core.js"],
        "ServiceNow": ["servicenow.com"],
        "Jira": ["atlassian-jira"],
        "Zendesk": ["zendesk.com", "zdassets.com"],
    }
}

# WAF detection signatures (Expanded)
WAF_SIGNATURES = [
    ("cloudflare", "cookie:__cfduid", "Cloudflare"),
    ("cloudflare", "server:cloudflare", "Cloudflare"),
    ("awselb", "server:awselb", "AWS ELB"),
    ("cloudfront", "via:cloudfront", "AWS CloudFront"),
    ("akamai", "server:akamai", "Akamai"),
    ("akamai", "via:akamai", "Akamai"),
    ("incapsula", "cookie:incap_ses", "Imperva Incapsula"),
    ("sucuri", "server:sucuri", "Sucuri"),
    ("mod_security", "server:mod_security", "ModSecurity"),
    ("comodo", "server:comodo", "Comodo WAF"),
    ("barracuda", "cookie:barra_counter_sd", "Barracuda WAF"),
    ("f5bigip", "cookie:bigipserver", "F5 BIG-IP"),
    ("fortinet", "server:fortiweb", "FortiWeb"),
    ("radware", "server:radware", "Radware"),
    ("aws_waf", "server:aws_waf", "AWS WAF"),
    ("azure_waf", "server:azure_waf", "Azure WAF"),
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
            ssl=False,
            allow_redirects=True
        ) as resp:
            if resp.status == 200:
                favicon = await resp.read()
                if len(favicon) > 0:
                    return mmh3.hash(codecs.encode(favicon, "base64"))
    except Exception:
        pass
    return None


def _detect_technologies(headers: Dict[str, str], body_text: str) -> Set[str]:
    """Detect technologies from response headers and body."""
    technologies = set()
    
    # Normalize headers for case-insensitive matching
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    server = headers_lower.get("server", "")
    powered_by = headers_lower.get("x-powered-by", "")
    
    # Check headers
    for tech, signatures in TECH_SIGNATURES["header"].items():
        for sig in signatures:
            sig_lower = sig.lower()
            if sig_lower in server or sig_lower in powered_by:
                technologies.add(tech)
                break
    
    # Check body
    body_lower = body_text.lower()
    for tech, signatures in TECH_SIGNATURES["body"].items():
        for sig in signatures:
            if sig.lower() in body_lower:
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


def get_cert_from_response(response: aiohttp.ClientResponse) -> str:
    """Extract SSL Common Name from an active aiohttp response."""
    try:
        if response.connection and response.connection.transport:
            ssl_obj = response.connection.transport.get_extra_info('ssl_object')
            if ssl_obj:
                cert_bin = ssl_obj.getpeercert(binary_form=True)
                return parse_certificate(cert_bin)
    except Exception:
        pass
    return ""


async def unified_probe(
    session: aiohttp.ClientSession,
    ip: str,
    port: int,
    config
) -> Optional[Dict[str, Any]]:
    """
    Unified probe that gathers all data (SSL, HTTP, Favicon, WAF, Tech) 
    in a single efficient flow.
    """
    ssl_ports = {443, 8443, 4443, 9443}
    protocol = "https://" if port in ssl_ports else "http://"
    
    url = f"{protocol}{ip}:{port}"
    try:
        async with session.get(url, timeout=config.timeout, allow_redirects=True, ssl=False) as resp:
            status_code = resp.status
            response_headers = dict(resp.headers)
            cookies = response_headers.get("Set-Cookie", "")
            
            # 1. Extract SSL CN from the same connection
            common_name = get_cert_from_response(resp)
            
            # 2. Get Response Body
            body = await resp.text(errors='ignore')
            
            # 3. Detect Tech & WAF
            techs = _detect_technologies(response_headers, body)
            waf = _detect_waf(response_headers, cookies)
            
            # 4. Get Favicon (Try to reuse session/connection)
            fav_hash = await get_favicon_hash(session, f"{protocol}{ip}:{port}", config.timeout)
            
            # 5. JARM (Separate Probe sadly, but only if HTTPS)
            jarm_hash = None
            if protocol == "https://":
                jarm_hash = await asyncio.to_thread(get_jarm_hash, ip, port)

            # Summarize result
            first_300_words = " ".join(body.split()[:300])
            
            # Format according to existing schema
            result = {
                "title": _extract_title(body),
                "request": url,
                "redirected_url": str(resp.url) if str(resp.url) != url else None,
                "ip": ip,
                "port": str(port),
                "domain": common_name,
                "response_text": first_300_words,
                "response_headers": response_headers,
                "favicon_hash": fav_hash,
                "jarm_hash": jarm_hash,
                "technologies": list(techs),
                "waf": waf,
                "status_code": status_code
            }
            
            return {f'{protocol.replace("://", "")}_responseForIP': result}

    except Exception:
        # If HTTPS failed, maybe it was HTTP on 443 (rare but happens)
        # Or if HTTP failed, maybe it was HTTPS on a non-standard port.
        pass
    return None


def _extract_title(html: str) -> str:
    """
    Extract page title from HTML with multiple fallback methods.
    
    Tries in order:
    1. <title> tag
    2. og:title meta tag  
    3. <h1> tag
    4. First significant text
    """
    if not html:
        return "No Title"
        
    try:
        # Method 1: Try standard title tag with BeautifulSoup
        soup = BeautifulSoup(html, 'lxml', parse_only=_HTML_STRAINER)
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
            if title:
                return title[:200]  # Limit title length
        
        # Method 2: Try regex for title (faster for malformed HTML)
        import re
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            if title:
                return title[:200]
        
        # Method 3: Try og:title meta tag
        og_match = re.search(r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if not og_match:
            og_match = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:title["\']', html, re.IGNORECASE)
        if og_match:
            title = og_match.group(1).strip()
            if title:
                return title[:200]
        
        # Method 4: Try h1 tag
        h1_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html, re.IGNORECASE | re.DOTALL)
        if h1_match:
            title = h1_match.group(1).strip()
            if title:
                return title[:200]
        
        return "No Title"
    except Exception:
        return "No Title"



async def check_site(
    session: aiohttp.ClientSession,
    ip: str,
    port: int,
    config
) -> Optional[Dict[str, Any]]:
    """
    Optimized entry point for a single IP+Port target.
    """
    try:
        # We start with a unified probe on the specific port found
        return await unified_probe(session, ip, port, config)
    except Exception as e:
        log_to_server(f"Critical Error for {ip}:{port}: {e}")
    return None