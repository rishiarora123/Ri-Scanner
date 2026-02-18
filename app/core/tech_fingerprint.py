"""
Technology Fingerprinting - Phase 2 Enhancement
Wappalyzer-style detection of technologies, frameworks, libraries
"""

import httpx
import re
from typing import List, Dict, Set
from urllib.parse import urljoin

# Common User-Agent to avoid blocking
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

class TechFingerprint:
    """Detect technologies from HTML, headers, JS patterns"""
    
    # Signature patterns for common technologies
    SIGNATURES = {
        "Frameworks": {
            "React": [r"/__REACT_DEVTOOLS_GLOBAL_HOOK__", r"react\.production\.min\.js", r"react-root", r"ReactDOM"],
            "Vue.js": [r"__vue__", r"vue\.min\.js", r"v-app", r"vue-js"],
            "Angular": [r"ng-app", r"data-ng-", r"angular\.min\.js", r"ng-binding", r"ng-scope"],
            "Django": [r"csrfmiddlewaretoken", r"Django/", r"django-debug-toolbar"],
            "Flask": [r"flask", r"werkzeug", r"flask-socketio"],
            "Next.js": [r"__NEXT_", r"_next/static", r"next-route-announcer"],
            "Laravel": [r"XSRF-TOKEN", r"laravel_session", r"Laravel"],
            "Spring Boot": [r"spring-webmvc", r"org.springframework", r"JSESSIONID"],
            "Ruby on Rails": [r"rails", r"X-Runtime", r"csrf-param"],
            "Express": [r"X-Powered-By: Express", r"express\.js"],
            "Svelte": [r"svelte-", r"__svelte"],
        },
        "Server Software": {
            "Apache": [r"Apache", r"Apache/2", r"mod_ssl"],
            "Nginx": [r"nginx", r"nginx/1"],
            "Microsoft IIS": [r"IIS/", r"Microsoft-IIS"],
            "LiteSpeed": [r"LiteSpeed"],
            "Cloudflare Server": [r"cloudflare"],
            "Traefik": [r"traefik"],
            "Haproxy": [r"haproxy"],
            "OpenResty": [r"openresty"],
        },
        "CMS": {
            "WordPress": [r"wp-content", r"wp-includes", r"wordpress", r"wp-json"],
            "Joomla": [r"joomla", r"/images/logo\.png", r"com_content"],
            "Drupal": [r"drupal\.org", r"sites/all", r"Drupal"],
            "Magento": [r"magento", r"skin/frontend", r"Mage.Cookies"],
            "Shopify": [r"Shopify\.shop", r"cdn/shop", r"shopify-payment-button"],
            "Ghost": [r"Ghost", r"ghost-version"],
        },
        "JavaScript Libraries": {
            "jQuery": [r"jquery\.min\.js", r"\$\.noConflict", r"jQuery\."],
            "Bootstrap": [r"bootstrap\.min\.css", r"bs-navbar", r"bootstrap\.js"],
            "Font Awesome": [r"fontawesome", r"font-awesome", r"fa-"],
            "Axios": [r"axios", r"axios\.min\.js"],
            "Lodash": [r"_\.", r"lodash"],
            "Moment.js": [r"moment\.min\.js"],
            "Three.js": [r"three\.js", r"three\.min\.js"],
        },
        "Analytics": {
            "Google Analytics": [r"google-analytics\.com", r"gtag\.js", r"UA-", r"G-"],
            "Mixpanel": [r"mixpanel\.com"],
            "Segment": [r"segment\.com"],
            "Hotjar": [r"hotjar\.com"],
            "GTM": [r"googletagmanager\.com", r"GTM-"],
        },
        "Security": {
            "reCAPTCHA": [r"recaptcha", r"g-recaptcha"],
            "Cloudflare": [r"cdn-cgi", r"__cfduid", r"cf-ray"],
            "Akamai": [r"akamai", r"akamai-hd"],
            "Imperva": [r"incap_ses", r"visid_incap"],
        }
    }
    
    async def fingerprint_all(self, domain: str, html: str = None, headers: Dict = None) -> Dict:
        """Master fingerprinting function"""
        
        results = {
            "from_html": [],
            "from_headers": [],
            "from_javascript": [],
            "from_meta": [],
            "from_cookies": [],
            "confidence": {}
        }
        
        # Fetch HTML if not provided
        if not html:
            try:
                async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                    response = await client.get(f"https://{domain}")
                    html = response.text
            except:
                html = ""
        
        # Fetch headers if not provided
        if not headers:
            try:
                async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                    response = await client.get(f"https://{domain}")
                    headers = dict(response.headers)
            except:
                headers = {}
        
        # Run all detection methods
        if html:
            results["from_html"] = self._detect_from_html(html)
            results["from_meta"] = self._detect_from_meta(html)
            results["from_javascript"] = self._detect_from_js_patterns(html)
        
        if headers:
            results["from_headers"] = self._detect_from_headers(headers)
            results["from_cookies"] = self._detect_from_cookies(headers.get("Set-Cookie", ""))
        
        # Aggregate, score and categorize
        all_techs = {}
        tech_to_category = {}
        
        # Categorize by looking up in SIGNATURES
        def _get_category(tech_name):
            for cat, techs in self.SIGNATURES.items():
                if tech_name in techs:
                    return cat
            return "Other"

        # Weights: 
        # Headers/Cookies/Meta: 2 points (High fidelity)
        # HTML/JS patterns: 1 point (Lower fidelity)
        source_weights = {
            "from_headers": 2.0,
            "from_cookies": 2.0,
            "from_meta": 1.5,
            "from_html": 1.0,
            "from_javascript": 1.0
        }

        for source, techs in results.items():
            if source != "confidence" and isinstance(techs, list):
                weight = source_weights.get(source, 1.0)
                for tech in techs:
                    if tech not in all_techs:
                        all_techs[tech] = 0.0
                        tech_to_category[tech] = _get_category(tech)
                    all_techs[tech] += weight
        
        # Assign confidence based on total weight
        for tech, score in all_techs.items():
            if score >= 3.0:
                confidence = "high"
            elif score >= 2.0:
                confidence = "medium"
            else:
                confidence = "low"
            results["confidence"][tech] = confidence
        
        return {
            "total_technologies": len(all_techs),
            "technologies": sorted(list(all_techs.keys())),
            "categorized_techs": tech_to_category,
            "detection_sources": results,
            "confidence_scores": results["confidence"]
        }
    
    def _detect_from_html(self, html: str) -> List[str]:
        """Detect technologies from HTML content"""
        detected = []
        
        for category, techs in self.SIGNATURES.items():
            for tech, patterns in techs.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        if tech not in detected:
                            detected.append(tech)
                        break
        
        return detected
    
    def _detect_from_headers(self, headers: Dict) -> List[str]:
        """Detect technologies from HTTP headers"""
        detected = []
        
        # Check specific headers
        header_checks = {
            "Server": self.SIGNATURES.get("Server Software", {}),
            "X-Powered-By": {
                "PHP": [r"PHP"],
                "Express": [r"Express"],
                "ASP.NET": [r"ASP.NET"],
            },
            "X-AspNet-Version": {
                "ASP.NET": [r".*"]
            },
            "X-Runtime": {
                "Ruby": [r".*"]
            }
        }
        
        for header, tech_patterns in header_checks.items():
            header_value = headers.get(header, "")
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, header_value, re.IGNORECASE):
                        if tech not in detected:
                            detected.append(tech)
                        break
        
        return detected
    
    def _detect_from_meta(self, html: str) -> List[str]:
        """Detect technologies from meta tags"""
        detected = []
        
        # Look for generator meta tag
        generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if generator_match:
            generator = generator_match.group(1)
            detected.append(generator)
        
        # Look for specific tech meta tags
        tech_metas = {
            "Wordpress": r'wordpress',
            "Drupal": r'drupal',
            "Joomla": r'joomla',
        }
        
        for tech, pattern in tech_metas.items():
            if re.search(pattern, html, re.IGNORECASE):
                if tech not in detected:
                    detected.append(tech)
        
        return detected
    
    def _detect_from_js_patterns(self, html: str) -> List[str]:
        """Detect from JavaScript patterns in HTML"""
        detected = []
        
        # Extract script content
        scripts = re.findall(r'<script[^>]*>([^<]*)</script>', html, re.IGNORECASE | re.DOTALL)
        script_text = " ".join(scripts)
        
        # Look for JS library patterns
        js_libraries = {
            "jQuery": [r"\$\(", r"jQuery\(", r"jQuery\."],
            "React": [r"React\.createElement", r"ReactDOM"],
            "Vue.js": [r"Vue\(", r"new Vue\("],
            "Angular": [r"angular\.module", r"\$scope"],
            "Lodash": [r"_\.", r"lodash"],
            "Bootstrap": [r"\$\.modal", r"Bootstrap"],
        }
        
        for lib, patterns in js_libraries.items():
            for pattern in patterns:
                if re.search(pattern, script_text, re.IGNORECASE):
                    if lib not in detected:
                        detected.append(lib)
                    break
        
        return detected
    
    def _detect_from_cookies(self, set_cookie: str) -> List[str]:
        """Detect from Set-Cookie headers"""
        detected = []
        
        cookie_patterns = {
            "WordPress": r"wordpress_",
            "Joomla": r"Joomla",
            "Drupal": r"DRUPAL\.sid",
            "Magento": r"frontend=",
            "Shopify": r"_shop_session",
        }
        
        for tech, pattern in cookie_patterns.items():
            if re.search(pattern, set_cookie, re.IGNORECASE):
                if tech not in detected:
                    detected.append(tech)
        
        return detected
