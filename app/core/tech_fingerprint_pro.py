"""
Tech Fingerprint Pro — comprehensive technology/version detection for any
URL or IP, using only free / open-source data sources.

Detection methods (run in parallel where possible):

  1. HTTP probe       — headers, cookies, body, meta tags, scripts, links
  2. Common-path probe — /robots.txt, /sitemap.xml, /wp-login.php, /admin,
                         /administrator, /api-docs, /actuator, /.env (don't fetch),
                         /server-status, /nginx_status
  3. Favicon hash      — mmh3 hash matched against a curated DB (Shodan-style)
  4. TLS certificate   — issuer, subject, SANs, validity
  5. Banner grab       — for non-HTTP ports (SSH/SMTP/FTP/MySQL/Redis/etc.)
  6. Shodan InternetDB — https://internetdb.shodan.io/<ip> (free, no auth,
                         returns ports, hostnames, CPEs, known CVEs)
  7. Reverse-DNS hint  — PTR / hostname patterns
  8. Wappalyzer-style signature engine — built-in 80+ tech patterns

Outputs:
  - List of detected technologies with categories, versions, confidence
  - List of known CVEs / vulns (from Shodan InternetDB)
  - Raw probe data for audit

All requests use a short timeout (5s default), are rate-limited per-host,
and never POST anything anywhere.
"""

import asyncio
import re
import socket
import ssl
import json
import time
import struct
import codecs
from base64 import b64decode
from hashlib import sha256
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

import httpx
import mmh3

# h2 is optional — when present, HTTP/2 probing is used
try:
    import h2  # noqa: F401
    _HAS_H2 = True
except ImportError:
    _HAS_H2 = False


# ── Built-in Tech Signatures ──────────────────────────────────────────
# Each signature is matched against probe data (headers/body/cookies/etc.)
# and returns the tech name, category, and version-extracting regex.
#
# Sources adapted from the public-domain / open Wappalyzer-style data sets
# (enthec/webappanalyzer, AliasIO/wappalyzer) plus hand-curated additions.

SIGNATURES: List[Dict[str, Any]] = [
    # ── CMS ────────────────────────────────────────────────────────
    {"name": "WordPress", "category": "CMS",
     "html": [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)?'],
     "headers": {"link": r'wp-json'},
     "cookies": [r'^wp-settings-\d', r'^wordpress_'],
     "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"],
     "scripts": [r'/wp-content/', r'/wp-includes/'],
     "cpe": "cpe:2.3:a:wordpress:wordpress"},

    {"name": "Drupal", "category": "CMS",
     "html": [r'<meta[^>]+name=["\']Generator["\'][^>]+content=["\']Drupal\s*(\d+)'],
     "headers": {"x-generator": r'Drupal\s*(\d+)', "x-drupal-cache": r'.+'},
     "cookies": [r'^SESS[a-f\d]{32}'],
     "paths": ["/sites/default/", "/user/login", "/?q=user/login"],
     "cpe": "cpe:2.3:a:drupal:drupal"},

    {"name": "Joomla", "category": "CMS",
     "html": [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!?\s*([\d.]+)?',
              r'/media/system/js/'],
     "paths": ["/administrator/", "/components/", "/templates/"],
     "cpe": "cpe:2.3:a:joomla:joomla"},

    {"name": "Magento", "category": "CMS",
     "html": [r'Mage\.Cookies', r'/skin/frontend/(?:default|base)/',
              r'/static/version\d+/', r'var\s+BLANK_URL\s*=.+Mage'],
     "cookies": [r'^frontend=[a-f0-9]{26}$'],
     "cpe": "cpe:2.3:a:magento:magento"},

    {"name": "Shopify", "category": "CMS",
     "headers": {"x-shopid": r'.+', "x-shopify-stage": r'.+'},
     "html": [r'cdn\.shopify\.com', r'Shopify\.theme']},

    {"name": "Ghost", "category": "CMS",
     "html": [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Ghost\s*([\d.]+)?'],
     "headers": {"x-powered-by": r'Express'}},

    {"name": "Wix", "category": "CMS",
     "html": [r'wix\.com', r'wixstatic\.com']},

    # ── Web frameworks ─────────────────────────────────────────────
    {"name": "Laravel", "category": "Framework",
     "cookies": [r'^laravel_session=', r'^XSRF-TOKEN='],
     "headers": {"set-cookie": r'laravel_session'},
     "cpe": "cpe:2.3:a:laravel:laravel"},

    {"name": "Django", "category": "Framework",
     "cookies": [r'^csrftoken=[A-Za-z0-9]{32,}', r'^django_session='],
     "html": [r'csrfmiddlewaretoken'],
     "cpe": "cpe:2.3:a:djangoproject:django"},

    {"name": "Flask", "category": "Framework",
     "cookies": [r'^session=eyJ'],
     "headers": {"server": r'Werkzeug/([\d.]+)?'}},

    {"name": "Ruby on Rails", "category": "Framework",
     "cookies": [r'^_session_id=', r'^_rails_', r'^_[a-z0-9_-]+_session='],
     "headers": {"x-powered-by": r'Phusion Passenger',
                 "x-runtime": r'.+',
                 "x-request-id": r'^[a-f0-9-]{32,}'},
     "html": [r'csrf-param.*authenticity_token',
              r'<meta\s+name=["\']csrf-param["\']']},

    {"name": "GitHub", "category": "Platform",
     "headers": {"server": r'github\.com', "x-github-": r'.+'},
     "cookies": [r'^_gh_sess=', r'^_octo='],
     "html": [r'data-github-', r'github-light\.css', r'<meta[^>]+name=["\']octolytics-']},

    {"name": "Express", "category": "Framework",
     "headers": {"x-powered-by": r'Express'}},

    {"name": "Next.js", "category": "Framework",
     "html": [r'/_next/static/', r'__NEXT_DATA__'],
     "headers": {"x-powered-by": r'Next\.js\s*([\d.]+)?',
                 "x-nextjs-cache": r'.+'},
     "cpe": "cpe:2.3:a:vercel:next.js"},

    {"name": "Nuxt.js", "category": "Framework",
     "html": [r'window\.__NUXT__', r'<div id="__nuxt"'],
     "headers": {"x-powered-by": r'Nuxt\s*([\d.]+)?'}},

    {"name": "ASP.NET", "category": "Framework",
     "headers": {"x-aspnet-version": r'([\d.]+)',
                 "x-aspnetmvc-version": r'([\d.]+)',
                 "x-powered-by": r'ASP\.NET'},
     "cookies": [r'^ASP\.NET_SessionId=', r'^\.ASPXAUTH='],
     "cpe": "cpe:2.3:a:microsoft:asp.net"},

    {"name": "Spring Boot", "category": "Framework",
     "headers": {"x-application-context": r'.+'},
     "paths": ["/actuator", "/actuator/info", "/actuator/health"],
     "cpe": "cpe:2.3:a:vmware:spring_boot"},

    {"name": "Symfony", "category": "Framework",
     "headers": {"x-debug-token": r'.+', "x-symfony-cache": r'.+'},
     "cookies": [r'^sf_redirect=']},

    {"name": "CodeIgniter", "category": "Framework",
     "cookies": [r'^ci_session=', r'^ci_csrf_'],
     "html": [r'CodeIgniter']},

    {"name": "Phoenix (Elixir)", "category": "Framework",
     "cookies": [r'^_phoenix_'],
     "headers": {"x-request-id": r'.+'}},

    # ── Web servers ────────────────────────────────────────────────
    {"name": "Apache", "category": "Web server",
     "headers": {"server": r'(?:Apache(?:-Coyote)?)(?:/([\d.]+))?'},
     "cpe": "cpe:2.3:a:apache:http_server"},

    {"name": "Nginx", "category": "Web server",
     "headers": {"server": r'nginx(?:/([\d.]+))?'},
     "cpe": "cpe:2.3:a:nginx:nginx"},

    {"name": "Microsoft-IIS", "category": "Web server",
     "headers": {"server": r'Microsoft-IIS/([\d.]+)?'},
     "cpe": "cpe:2.3:a:microsoft:internet_information_services"},

    {"name": "LiteSpeed", "category": "Web server",
     "headers": {"server": r'LiteSpeed', "x-litespeed-cache": r'.+'},
     "cpe": "cpe:2.3:a:litespeedtech:openlitespeed"},

    {"name": "Caddy", "category": "Web server",
     "headers": {"server": r'Caddy'}},

    {"name": "OpenResty", "category": "Web server",
     "headers": {"server": r'openresty(?:/([\d.]+))?'}},

    {"name": "Cherokee", "category": "Web server",
     "headers": {"server": r'Cherokee(?:/([\d.]+))?'}},

    {"name": "Lighttpd", "category": "Web server",
     "headers": {"server": r'lighttpd(?:/([\d.]+))?'}},

    {"name": "Tornado", "category": "Web server",
     "headers": {"server": r'TornadoServer(?:/([\d.]+))?'}},

    {"name": "Gunicorn", "category": "Web server",
     "headers": {"server": r'gunicorn(?:/([\d.]+))?'}},

    {"name": "Uvicorn", "category": "Web server",
     "headers": {"server": r'uvicorn'}},

    # ── Language / runtime ─────────────────────────────────────────
    {"name": "PHP", "category": "Language",
     "headers": {"x-powered-by": r'PHP/([\d.]+)?', "set-cookie": r'PHPSESSID='},
     "cookies": [r'^PHPSESSID='],
     "cpe": "cpe:2.3:a:php:php"},

    {"name": "Node.js", "category": "Language",
     "headers": {"x-powered-by": r'(?:Express|Next\.js|Nuxt|Node\.js)'},
     "cpe": "cpe:2.3:a:nodejs:nodejs"},

    {"name": "Python", "category": "Language",
     "headers": {"server": r'(?:gunicorn|uvicorn|Werkzeug|TornadoServer|CherryPy)'}},

    # ── CDN / Edge / Reverse proxy ────────────────────────────────
    {"name": "Cloudflare", "category": "CDN",
     "headers": {"cf-ray": r'.+', "cf-cache-status": r'.+', "server": r'cloudflare'},
     "cookies": [r'^__cf_bm=', r'^__cflb=', r'^cf_clearance=']},

    {"name": "AWS CloudFront", "category": "CDN",
     "headers": {"x-amz-cf-id": r'.+', "via": r'CloudFront'}},

    {"name": "Fastly", "category": "CDN",
     "headers": {"x-served-by": r'cache-', "x-cache": r'.+', "x-fastly": r'.+',
                 "fastly-debug-digest": r'.+'}},

    {"name": "Akamai", "category": "CDN",
     "headers": {"x-akamai-": r'.+', "akamai-grn": r'.+',
                 "server": r'AkamaiGHost'}},

    {"name": "Sucuri", "category": "CDN/WAF",
     "headers": {"x-sucuri-id": r'.+', "x-sucuri-cache": r'.+',
                 "server": r'Sucuri'}},

    {"name": "Imperva Incapsula", "category": "CDN/WAF",
     "headers": {"x-iinfo": r'.+', "x-cdn": r'Incapsula'},
     "cookies": [r'^incap_ses', r'^visid_incap_']},

    {"name": "Vercel", "category": "Hosting",
     "headers": {"server": r'Vercel', "x-vercel-id": r'.+', "x-vercel-cache": r'.+'}},

    {"name": "Netlify", "category": "Hosting",
     "headers": {"server": r'Netlify', "x-nf-request-id": r'.+'}},

    {"name": "GitHub Pages", "category": "Hosting",
     "headers": {"server": r'GitHub\.com'}},

    {"name": "Heroku", "category": "Hosting",
     "headers": {"via": r'vegur', "x-heroku-": r'.+'}},

    # ── WAF ────────────────────────────────────────────────────────
    {"name": "AWS WAF", "category": "WAF",
     "headers": {"x-amzn-waf": r'.+'}},

    {"name": "ModSecurity", "category": "WAF",
     "headers": {"server": r'Mod_Security'}},

    {"name": "F5 BIG-IP", "category": "WAF",
     "cookies": [r'^BIGipServer', r'^TS01'],
     "headers": {"server": r'BIG-IP'}},

    {"name": "Barracuda WAF", "category": "WAF",
     "cookies": [r'^barra_counter_session=']},

    # ── JS Libraries ──────────────────────────────────────────────
    {"name": "jQuery", "category": "JS Library",
     "scripts": [r'jquery[.-](\d[\d.]*)\.(?:min\.)?js', r'/jquery/(\d[\d.]*)/jquery'],
     "html": [r'jQuery v(\d[\d.]*)', r'jquery@(\d[\d.]*)']},

    {"name": "React", "category": "JS Library",
     "html": [r'<div[^>]+id=["\']root["\']', r'react(?:-dom)?[.-](\d[\d.]*)\.'],
     "scripts": [r'react@(\d[\d.]*)/']},

    {"name": "Vue.js", "category": "JS Library",
     "html": [r'<div[^>]+id=["\']app["\'][^>]*>\s*<\!--', r'Vue\.version'],
     "scripts": [r'vue@(\d[\d.]*)/dist', r'vue[.-](\d[\d.]*)\.js']},

    {"name": "AngularJS", "category": "JS Library",
     "html": [r'\bng-app\b', r'ng-controller'],
     "scripts": [r'angular[.-]?(\d[\d.]*)\.js']},

    {"name": "Angular", "category": "JS Library",
     "html": [r'ng-version=["\'](\d[\d.]*)']},

    {"name": "Bootstrap", "category": "CSS Framework",
     "scripts": [r'bootstrap[.-](\d[\d.]*)\.(?:min\.)?js'],
     "html": [r'bootstrap@(\d[\d.]*)/', r'bootstrap[.-](\d[\d.]*)\.(?:min\.)?css']},

    {"name": "Tailwind CSS", "category": "CSS Framework",
     "html": [r'tailwind@(\d[\d.]*)/', r'tailwindcss[.-]?(\d[\d.]*)']},

    {"name": "Lodash", "category": "JS Library",
     "scripts": [r'lodash[.-](\d[\d.]*)\.']},

    {"name": "Moment.js", "category": "JS Library",
     "scripts": [r'moment[.-](\d[\d.]*)\.']},

    {"name": "D3.js", "category": "JS Library",
     "scripts": [r'd3[.-]?(\d[\d.]*)\.']},

    {"name": "Three.js", "category": "JS Library",
     "scripts": [r'three[.-]?(\d[\d.]*)\.']},

    # ── Analytics & tracking ──────────────────────────────────────
    {"name": "Google Analytics", "category": "Analytics",
     "scripts": [r'google-analytics\.com/(?:ga\.js|analytics\.js|gtag/js)',
                 r'googletagmanager\.com/gtag/js'],
     "html": [r"gtag\(\s*['\"]config['\"]"]},

    {"name": "Google Tag Manager", "category": "Analytics",
     "scripts": [r'googletagmanager\.com/gtm\.js']},

    {"name": "Facebook Pixel", "category": "Analytics",
     "scripts": [r'connect\.facebook\.net/en_US/fbevents\.js'],
     "html": [r'fbq\(\s*["\']init["\']']},

    {"name": "Hotjar", "category": "Analytics",
     "scripts": [r'static\.hotjar\.com/c/hotjar-']},

    {"name": "Mixpanel", "category": "Analytics",
     "scripts": [r'mixpanel\.com/[\w/.-]+\.js'],
     "html": [r'mixpanel\.init\(']},

    # ── Dev tools / DevOps surfaces ────────────────────────────────
    {"name": "GitLab", "category": "Dev tool",
     "html": [r'<meta[^>]+content=["\']GitLab\b'],
     "headers": {"x-gitlab-meta": r'.+'},
     "paths": ["/users/sign_in", "/explore"]},

    {"name": "Jenkins", "category": "Dev tool",
     "headers": {"x-jenkins": r'([\d.]+)', "x-jenkins-cli2-port": r'.+'},
     "html": [r'X-Jenkins:'],
     "cpe": "cpe:2.3:a:jenkins:jenkins"},

    {"name": "Jira", "category": "Dev tool",
     "html": [r'<meta[^>]+name=["\']application-name["\'][^>]+content=["\']JIRA',
              r'jira-issue-status'],
     "cookies": [r'^JSESSIONID=']},

    {"name": "Confluence", "category": "Dev tool",
     "html": [r'<meta[^>]+name=["\']application-name["\'][^>]+content=["\']Confluence']},

    {"name": "phpMyAdmin", "category": "Database admin",
     "html": [r'<title>\s*phpMyAdmin\b'],
     "cookies": [r'^phpMyAdmin='],
     "cpe": "cpe:2.3:a:phpmyadmin:phpmyadmin"},

    {"name": "Adminer", "category": "Database admin",
     "html": [r'<a[^>]+href=["\']https://www\.adminer\.org']},

    {"name": "Kibana", "category": "Monitoring",
     "headers": {"kbn-name": r'.+', "kbn-version": r'([\d.]+)'}},

    {"name": "Grafana", "category": "Monitoring",
     "headers": {"x-grafana-": r'.+'},
     "html": [r'<title>\s*Grafana\b']},

    {"name": "Prometheus", "category": "Monitoring",
     "paths": ["/metrics", "/-/healthy", "/-/ready"],
     "html": [r'<title>\s*Prometheus\b']},

    # ── Other common ──────────────────────────────────────────────
    {"name": "Cloudflare Workers", "category": "Edge",
     "headers": {"cf-worker": r'.+'}},

    {"name": "Varnish", "category": "Cache",
     "headers": {"x-varnish": r'.+', "via": r'varnish'}},

    {"name": "Squid", "category": "Cache",
     "headers": {"server": r'squid', "via": r'squid'}},

    {"name": "HAProxy", "category": "Load balancer",
     "headers": {"server": r'HAProxy'}},

    {"name": "Traefik", "category": "Load balancer",
     "headers": {"server": r'Traefik'}},

    {"name": "Discourse", "category": "Forum",
     "headers": {"x-discourse-route": r'.+'}},

    {"name": "Mattermost", "category": "Collaboration",
     "headers": {"x-version-id": r'.+'},
     "cookies": [r'^MMAUTHTOKEN=']},
]


# ── Favicon-hash database (Shodan-style mmh3 hash → tech) ────────────
# Hashes are mmh3.hash() of base64(raw_favicon_bytes) — same algorithm Shodan
# uses. Values curated from public threat-intel data sets.

FAVICON_DB = {
    99405940:   ("Cisco ASA", "Security appliance"),
    -1297243708:("Apache Tomcat", "Web server"),
    -1922474137:("Microsoft Exchange OWA", "Mail server"),
    -1959429109:("VMware vSphere", "Virtualization"),
    1356662280: ("Gitea", "Dev tool"),
    -369057602: ("GitLab", "Dev tool"),
    1989537243: ("Jenkins", "Dev tool"),
    -1832903914:("Confluence", "Dev tool"),
    -990454900: ("Grafana", "Monitoring"),
    981038853:  ("Kibana", "Monitoring"),
    -1880503769:("phpMyAdmin", "Database admin"),
    810461447:  ("WordPress", "CMS"),
    -1655458429:("Joomla", "CMS"),
    -1031641451:("Drupal", "CMS"),
    -626592786: ("Synology DSM", "NAS"),
    -2024416028:("FortiGate", "Firewall"),
    -1672099234:("Pulse Connect Secure", "VPN"),
    -558895074: ("Citrix NetScaler ADC", "Load balancer"),
    -870143725: ("F5 BIG-IP", "Load balancer"),
}


def _favicon_mmh3(data: bytes) -> int:
    """Shodan-style favicon hash: base64-encode the favicon bytes line-wrapped
    at 76 cols, then mmh3.hash() the result."""
    encoded = codecs.encode(data, 'base64').decode('utf-8')
    return mmh3.hash(encoded)


# ── Banner regex for common service ports ───────────────────────────
SERVICE_BANNERS = {
    22:    [("OpenSSH", r'SSH-2\.0-OpenSSH_([\w.]+)')],
    21:    [("vsftpd", r'\(vsFTPd\s+([\d.]+)\)'),
            ("ProFTPD", r'ProFTPD\s+([\d.]+)')],
    25:    [("Postfix", r'Postfix'),
            ("Exim", r'Exim\s+([\d.]+)'),
            ("Sendmail", r'Sendmail')],
    110:   [("Dovecot", r'\+OK.*Dovecot')],
    143:   [("Dovecot", r'IMAP4rev1.*Dovecot')],
    3306:  [("MySQL", r'^.\x00\x00\x00\n([\d.]+)')],
    5432:  [("PostgreSQL", r'PostgreSQL')],
    6379:  [("Redis", r'-NOAUTH\|.*ERR')],
    27017: [("MongoDB", r'MongoDB')],
    9200:  [("Elasticsearch", r'"cluster_name"')],
}


# ── Common probe paths (HEAD only, never POST) ─────────────────────
COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/wp-login.php", "/wp-json/", "/administrator/", "/admin/",
    "/login", "/users/sign_in", "/auth/login",
    "/server-status", "/nginx_status",
    "/actuator", "/actuator/info", "/actuator/health",
    "/api/", "/api-docs", "/swagger-ui/", "/swagger.json", "/openapi.json",
    "/_next/static/", "/graphql",
    "/.git/HEAD", "/.env", "/composer.json", "/package.json",
    "/phpinfo.php", "/info.php", "/phpmyadmin/",
]


class TechFingerprinter:
    """Comprehensive tech/version fingerprinter for a URL or IP."""

    def __init__(self, timeout: float = 6.0, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        )

    # ── Public entry point ────────────────────────────────────────
    async def fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Fingerprint a target. `target` may be:
          - URL  (https://example.com)
          - host (example.com)
          - IP   (1.2.3.4)
        """
        # Normalize to URL
        url, host, ip = self._normalize_target(target)

        # Run all probes in parallel
        results = await asyncio.gather(
            self._http_probe(url),
            self._favicon_probe(url),
            self._common_paths_probe(url),
            self._tls_probe(host or ip),
            self._shodan_internetdb(ip or host),
            self._reverse_dns(host or ip),
            self._port_banner_probes(host or ip),
            return_exceptions=True,
        )
        http_data, favicon_data, paths_data, tls_data, sdb_data, rdns, banners = [
            r if not isinstance(r, Exception) else {} for r in results
        ]

        # Combine into single probe context
        probe = {
            "http": http_data or {},
            "favicon": favicon_data or {},
            "paths": paths_data or {},
            "tls": tls_data or {},
            "shodan_internetdb": sdb_data or {},
            "reverse_dns": rdns or {},
            "banners": banners or {},
        }

        # Apply signature engine
        detected = self._apply_signatures(probe)

        # Add favicon-based detection
        if probe["favicon"].get("hash") in FAVICON_DB:
            name, cat = FAVICON_DB[probe["favicon"]["hash"]]
            detected.append({
                "name": name, "category": cat, "version": None,
                "confidence": "high", "via": "favicon-hash",
            })

        # Add Shodan InternetDB tech (CPE-based)
        for cpe in probe["shodan_internetdb"].get("cpes", []):
            parts = cpe.split(":")
            if len(parts) >= 5:
                name = f"{parts[3]} {parts[4]}".replace("_", " ").strip()
                version = parts[5] if len(parts) > 5 and parts[5] != "*" else None
                detected.append({
                    "name": name.title(), "category": "Software (CPE)",
                    "version": version, "confidence": "high",
                    "via": "shodan-internetdb", "cpe": cpe,
                })

        # Deduplicate by name, keep highest-confidence + best version
        merged = self._merge_detections(detected)

        return {
            "target": target,
            "url": url,
            "host": host,
            "ip": ip,
            "technologies": merged,
            "vulnerabilities": probe["shodan_internetdb"].get("vulns", []),
            "open_ports": probe["shodan_internetdb"].get("ports", []),
            "hostnames": probe["shodan_internetdb"].get("hostnames", []),
            "tls": probe["tls"],
            "headers": probe["http"].get("headers", {}),
            "favicon_hash": probe["favicon"].get("hash"),
            "reverse_dns": probe["reverse_dns"],
            "banners": probe["banners"],
            "discovered_paths": probe["paths"].get("found", []),
            "probe_summary": {
                "http_status": probe["http"].get("status"),
                "title": probe["http"].get("title"),
                "server_header": probe["http"].get("headers", {}).get("server"),
            },
        }

    # ── Normalize target ──────────────────────────────────────────
    def _normalize_target(self, target: str) -> Tuple[str, Optional[str], Optional[str]]:
        target = target.strip()
        if "://" not in target:
            # Bare host or IP
            url = f"https://{target}"
        else:
            url = target

        parsed = urlparse(url)
        host = parsed.hostname
        try:
            socket.inet_aton(host)
            ip = host
            return url, None, ip
        except (OSError, TypeError):
            pass

        # Hostname — try to resolve
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            ip = None
        return url, host, ip

    # ── HTTP probe ─────────────────────────────────────────────────
    async def _http_probe(self, url: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=False, follow_redirects=True,
                http2=_HAS_H2, headers={"User-Agent": self.user_agent}
            ) as client:
                r = await client.get(url)
                body = r.text[:200_000]
                cookies = []
                for c in r.cookies.jar:
                    cookies.append(f"{c.name}={c.value or ''}")
                # Extract <title> and <meta generator>
                title_m = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
                generator_m = re.search(
                    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                    body, re.I,
                )
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)[:50]
                links = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', body, re.I)[:50]

                return {
                    "url": str(r.url),
                    "status": r.status_code,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "cookies": cookies,
                    "body": body,
                    "title": title_m.group(1).strip() if title_m else None,
                    "meta_generator": generator_m.group(1).strip() if generator_m else None,
                    "scripts": scripts,
                    "links": links,
                }
        except Exception as e:
            return {"error": str(e)}

    # ── Favicon hashing ───────────────────────────────────────────
    async def _favicon_probe(self, url: str) -> Dict[str, Any]:
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=False, follow_redirects=True,
                headers={"User-Agent": self.user_agent}
            ) as client:
                for path in ("/favicon.ico", "/static/favicon.ico", "/assets/favicon.ico"):
                    try:
                        r = await client.get(base + path)
                        if r.status_code == 200 and r.content:
                            h = _favicon_mmh3(r.content)
                            return {
                                "url": base + path,
                                "hash": h,
                                "size": len(r.content),
                                "sha256": sha256(r.content).hexdigest()[:16],
                            }
                    except Exception:
                        continue
        except Exception:
            pass
        return {}

    # ── Common-path probes ────────────────────────────────────────
    async def _common_paths_probe(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        sem = asyncio.Semaphore(10)

        async def probe_path(path):
            async with sem:
                try:
                    async with httpx.AsyncClient(
                        timeout=4, verify=False, follow_redirects=False,
                        headers={"User-Agent": self.user_agent}
                    ) as client:
                        r = await client.head(base + path)
                        # Only treat 200/401/403 as evidence of existence.
                        # Redirects (301/302) typically mean the path is a
                        # catch-all rewrite and tell us nothing about tech.
                        if r.status_code in (200, 401, 403):
                            return {
                                "path": path,
                                "status": r.status_code,
                                "size": int(r.headers.get("content-length", 0) or 0),
                                "type": r.headers.get("content-type", ""),
                            }
                except Exception:
                    pass
                return None

        results = await asyncio.gather(*(probe_path(p) for p in COMMON_PATHS))
        for r in results:
            if r is not None:
                found.append(r)
        return {"found": found}

    # ── TLS certificate probe ─────────────────────────────────────
    async def _tls_probe(self, host: Optional[str], port: int = 443) -> Dict[str, Any]:
        if not host:
            return {}
        loop = asyncio.get_running_loop()
        def get_cert():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        cipher = ssock.cipher()
                        version = ssock.version()
                        # Get raw der cert for fingerprint
                        der = ssock.getpeercert(binary_form=True)
                        fp = sha256(der).hexdigest()
                        return {
                            "subject": dict(x[0] for x in cert.get("subject", [])),
                            "issuer": dict(x[0] for x in cert.get("issuer", [])),
                            "version": cert.get("version"),
                            "serial": cert.get("serialNumber"),
                            "notBefore": cert.get("notBefore"),
                            "notAfter": cert.get("notAfter"),
                            "subjectAltName": [v for _, v in cert.get("subjectAltName", [])],
                            "tls_version": version,
                            "cipher": cipher[0] if cipher else None,
                            "fingerprint_sha256": fp,
                        }
            except Exception as e:
                return {"error": str(e)}
        return await loop.run_in_executor(None, get_cert)

    # ── Shodan InternetDB (free, no auth) ─────────────────────────
    async def _shodan_internetdb(self, ip: Optional[str]) -> Dict[str, Any]:
        """Query https://internetdb.shodan.io/<ip> — free, no auth, returns
        ports, hostnames, CPEs, and known CVEs for any IPv4."""
        if not ip:
            return {}
        # Try to resolve hostname → IP
        try:
            socket.inet_aton(ip)
        except OSError:
            try:
                ip = socket.gethostbyname(ip)
            except (socket.gaierror, OSError):
                return {}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=True,
                headers={"User-Agent": self.user_agent}
            ) as client:
                r = await client.get(f"https://internetdb.shodan.io/{ip}")
                if r.status_code == 200:
                    return r.json()
                return {"status": r.status_code}
        except Exception as e:
            return {"error": str(e)}

    # ── Reverse DNS ────────────────────────────────────────────────
    async def _reverse_dns(self, target: Optional[str]) -> Dict[str, Any]:
        if not target:
            return {}
        loop = asyncio.get_running_loop()
        def lookup():
            try:
                socket.inet_aton(target)
                hostname, aliases, _ = socket.gethostbyaddr(target)
                return {"ptr": hostname, "aliases": aliases}
            except OSError:
                try:
                    ip = socket.gethostbyname(target)
                    hostname, aliases, _ = socket.gethostbyaddr(ip)
                    return {"ip": ip, "ptr": hostname, "aliases": aliases}
                except (socket.gaierror, OSError):
                    return {}
        return await loop.run_in_executor(None, lookup)

    # ── Banner grabbing on common service ports ──────────────────
    async def _port_banner_probes(self, host: Optional[str]) -> Dict[str, Any]:
        if not host:
            return {}
        banners = {}
        sem = asyncio.Semaphore(8)

        async def grab(port):
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=3
                    )
                    try:
                        data = await asyncio.wait_for(reader.read(512), timeout=3)
                    except asyncio.TimeoutError:
                        data = b""
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=1)
                    except (asyncio.TimeoutError, Exception):
                        pass
                    if not data:
                        return
                    decoded = data.decode("utf-8", errors="replace").strip()
                    banners[port] = {"raw": decoded[:300]}
                    # Match against known signatures
                    for tech, pattern in SERVICE_BANNERS.get(port, []):
                        m = re.search(pattern, decoded)
                        if m:
                            ver = m.group(1) if m.groups() else None
                            banners[port]["tech"] = tech
                            banners[port]["version"] = ver
                            break
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

        await asyncio.gather(*(grab(p) for p in SERVICE_BANNERS.keys()))
        return banners

    # ── Signature engine ───────────────────────────────────────────
    def _apply_signatures(self, probe: Dict[str, Any]) -> List[Dict[str, Any]]:
        detected: List[Dict[str, Any]] = []
        http = probe.get("http", {})
        headers = {k.lower(): str(v) for k, v in http.get("headers", {}).items()}
        body = http.get("body", "") or ""
        cookies = http.get("cookies", [])
        scripts = http.get("scripts", [])
        meta_gen = http.get("meta_generator", "") or ""
        found_paths = {p.get("path") for p in probe.get("paths", {}).get("found", [])}

        for sig in SIGNATURES:
            version = None
            matched_via = []

            # Headers
            for header_name, pattern in (sig.get("headers") or {}).items():
                val = headers.get(header_name.lower())
                if val and re.search(pattern, val):
                    matched_via.append(f"header:{header_name}")
                    m = re.search(pattern, val)
                    if m.groups() and not version:
                        version = m.group(1)

            # HTML body
            for pattern in sig.get("html", []):
                m = re.search(pattern, body, re.I)
                if m:
                    matched_via.append("html")
                    if m.groups() and not version:
                        version = m.group(1)

            # Cookies
            for pattern in sig.get("cookies", []):
                for c in cookies:
                    if re.search(pattern, c):
                        matched_via.append("cookie")
                        break

            # Scripts
            for pattern in sig.get("scripts", []):
                for s in scripts:
                    m = re.search(pattern, s, re.I)
                    if m:
                        matched_via.append("script")
                        if m.groups() and not version:
                            version = m.group(1)
                        break

            # Meta generator
            if sig["name"].lower() in meta_gen.lower():
                matched_via.append("meta-generator")
                m = re.search(rf"{sig['name']}[^\d]*(\d[\d.]*)", meta_gen, re.I)
                if m and not version:
                    version = m.group(1)

            # Discovered paths
            for path in sig.get("paths", []):
                if path in found_paths:
                    matched_via.append(f"path:{path}")
                    break

            if not matched_via:
                continue

            # Confidence scoring:
            #   - Header/cookie/HTML match: strong evidence (header is hard to spoof)
            #   - Path-only match: weak — many sites have catch-all 200s on any path,
            #     so require at least one other signal to avoid false positives.
            strong_sources = [v for v in matched_via if not v.startswith("path:")]
            if not strong_sources:
                # path-only — only allowed if multiple distinct paths matched
                path_count = len([v for v in matched_via if v.startswith("path:")])
                if path_count < 2:
                    continue
                confidence = "low"
            elif len(matched_via) > 1:
                confidence = "high"
            else:
                confidence = "medium"

            detected.append({
                "name": sig["name"],
                "category": sig["category"],
                "version": version,
                "confidence": confidence,
                "via": ", ".join(sorted(set(matched_via))),
                "cpe": sig.get("cpe"),
            })

        return detected

    # ── Merge / dedupe detections ─────────────────────────────────
    def _merge_detections(self, detected: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for d in detected:
            name = d["name"]
            if name not in merged:
                merged[name] = d
                continue
            existing = merged[name]
            # Prefer entry with version
            if d.get("version") and not existing.get("version"):
                existing["version"] = d["version"]
            # Combine "via" sources
            via_set = set(existing.get("via", "").split(", "))
            via_set.update(d.get("via", "").split(", "))
            existing["via"] = ", ".join(sorted(v for v in via_set if v))
            # Upgrade confidence if multiple sources agree
            if len(via_set) > 1:
                existing["confidence"] = "high"
        # Sort by category, then name
        return sorted(merged.values(), key=lambda x: (x["category"], x["name"]))


# ── Module-level convenience ──────────────────────────────────────
_default_fingerprinter = TechFingerprinter()

async def fingerprint(target: str) -> Dict[str, Any]:
    """Run a full fingerprint on a URL or IP."""
    return await _default_fingerprinter.fingerprint(target)
