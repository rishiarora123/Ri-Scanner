"""
Ri-Scanner Pro - Recon Tools Configuration

Comprehensive configuration for 40+ reconnaissance tools with:
- Installation commands for multiple package managers
- Availability checking
- API key requirements
- Category organization
"""
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class Tool:
    """Represents a reconnaissance tool."""
    id: str
    name: str
    category: str
    description: str
    check_cmd: Optional[List[str]] = None  # Command to check if installed
    install_cmds: Dict[str, str] = field(default_factory=dict)  # Package manager -> install command
    requires_api: bool = False
    api_keys: List[str] = field(default_factory=list)  # Environment variable names for API keys
    api_url: Optional[str] = None  # URL to get API key
    usage_template: Optional[str] = None  # Command template with {domain}, {ip}, etc.
    requires_root: bool = False
    is_api_only: bool = False  # True for web APIs that don't need CLI


# Tool Categories
CATEGORIES = {
    "subdomain": {"name": "🔍 Subdomain Enumeration", "icon": "🔍"},
    "cert": {"name": "🌐 Certificate Transparency", "icon": "🌐"},
    "origin_ip": {"name": "🌍 Origin IP Discovery", "icon": "🌍"},
    "port_scan": {"name": "📡 Port Scanning", "icon": "📡"},
    "search_engine": {"name": "🛰️ Search Engine Scanners", "icon": "🛰️"},
    "url_discovery": {"name": "🔗 URL / Asset Discovery", "icon": "🔗"},
    "framework": {"name": "🧰 Recon Frameworks", "icon": "🧰"}
}


# Complete Tools Database
TOOLS: Dict[str, Tool] = {
    # ==================== SUBDOMAIN ENUMERATION ====================
    "subfinder": Tool(
        id="subfinder",
        name="Subfinder",
        category="subdomain",
        description="Fast passive subdomain enumeration tool by ProjectDiscovery",
        check_cmd=["subfinder", "-version"],
        install_cmds={
            "go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "brew": "brew install subfinder"
        },
        usage_template="subfinder -d {domain} -silent"
    ),
    "amass": Tool(
        id="amass",
        name="Amass",
        category="subdomain",
        description="In-depth attack surface mapping and asset discovery",
        check_cmd=["amass", "version"],
        install_cmds={
            "brew": "brew install amass",
            "go": "go install -v github.com/owasp-amass/amass/v4/...@master"
        },
        usage_template="amass enum -passive -d {domain}"
    ),
    "assetfinder": Tool(
        id="assetfinder",
        name="Assetfinder",
        category="subdomain",
        description="Find domains and subdomains potentially related to a given domain",
        check_cmd=["assetfinder", "-h"],
        install_cmds={
            "go": "go install -v github.com/tomnomnom/assetfinder@latest"
        },
        usage_template="assetfinder --subs-only {domain}"
    ),

    "chaos": Tool(
        id="chaos",
        name="Chaos",
        category="subdomain",
        description="ProjectDiscovery's Chaos dataset for subdomain discovery",
        check_cmd=["chaos", "-version"],
        install_cmds={
            "go": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        },
        requires_api=True,
        api_keys=["CHAOS_API_KEY"],
        api_url="https://chaos.projectdiscovery.io",
        usage_template="chaos -d {domain} -silent"
    ),

    "fierce": Tool(
        id="fierce",
        name="Fierce",
        category="subdomain",
        description="DNS reconnaissance tool for locating non-contiguous IP space",
        check_cmd=["fierce", "--help"],
        install_cmds={
            "pip": "pip install fierce"
        },
        usage_template="fierce --domain {domain}"
    ),
    "gobuster": Tool(
        id="gobuster",
        name="Gobuster",
        category="subdomain",
        description="Directory/File, DNS and VHost busting tool",
        check_cmd=["gobuster", "version"],
        install_cmds={
            "go": "go install -v github.com/OJ/gobuster/v3@latest",
            "brew": "brew install gobuster"
        },
        usage_template="gobuster dns -d {domain} -w wordlist.txt"
    ),
    "dnsx": Tool(
        id="dnsx",
        name="DNSx",
        category="subdomain",
        description="Fast and multi-purpose DNS toolkit",
        check_cmd=["dnsx", "-version"],
        install_cmds={
            "go": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        },
        usage_template="echo {domain} | dnsx -silent -a -resp"
    ),
    "sublist3r": Tool(
        id="sublist3r",
        name="Sublist3r",
        category="subdomain",
        description="Subdomain enumeration using search engines",
        check_cmd=["sublist3r", "--help"],
        install_cmds={
            "pip": "pip install sublist3r"
        },
        usage_template="sublist3r -d {domain}"
    ),

    "altdns": Tool(
        id="altdns",
        name="Altdns",
        category="subdomain",
        description="Subdomain discovery through permutation generation",
        check_cmd=["altdns", "--help"],
        install_cmds={
            "pip": "pip install py-altdns"
        },
        usage_template="altdns -i subdomains.txt -o permutations.txt -w words.txt"
    ),
    "anubis": Tool(
        id="anubis",
        name="Anubis",
        category="subdomain",
        description="Subdomain enumeration and information gathering tool",
        check_cmd=["anubis", "--help"],
        install_cmds={
            "pip": "pip install anubis-netsec"
        },
        usage_template="anubis -t {domain}"
    ),

    # ==================== CERTIFICATE TRANSPARENCY ====================
    "crtsh": Tool(
        id="crtsh",
        name="crt.sh",
        category="cert",
        description="Certificate Transparency log search (Sectigo)",
        is_api_only=True,
        api_url="https://crt.sh/?q=%.{domain}&output=json",
        usage_template="API: https://crt.sh/?q=%.{domain}&output=json"
    ),
    "certspotter": Tool(
        id="certspotter",
        name="Certspotter",
        category="cert",
        description="Certificate transparency monitoring and alerting",
        is_api_only=True,
        api_url="https://api.certspotter.com/v1/issuances?domain={domain}",
        usage_template="API: https://api.certspotter.com/v1/issuances"
    ),
    "bufferover": Tool(
        id="bufferover",
        name="Bufferover",
        category="cert",
        description="DNS and TLS data from Rapid7 datasets",
        is_api_only=True,
        api_url="https://dns.bufferover.run/dns?q=.{domain}",
        usage_template="API: https://dns.bufferover.run/dns"
    ),
    "facebookct": Tool(
        id="facebookct",
        name="Facebook CT",
        category="cert",
        description="Facebook Certificate Transparency monitor (deprecated - use crt.sh instead)",
        is_api_only=True,
        requires_api=False,  # No longer requires API - deprecated service
        api_keys=[],
        api_url="https://developers.facebook.com/docs/certificate-transparency",
        usage_template="Use crt.sh instead - Facebook CT deprecated"
    ),

    # ==================== ORIGIN IP DISCOVERY ====================

    "dnsrecon": Tool(
        id="dnsrecon",
        name="DNSRecon",
        category="origin_ip",
        description="DNS enumeration and scanning tool",
        check_cmd=["dnsrecon", "--help"],
        install_cmds={
            "pip": "pip install dnsrecon",
            "brew": "brew install dnsrecon"
        },
        usage_template="dnsrecon -d {domain}"
    ),


    # ==================== PORT SCANNING ====================
    "nmap": Tool(
        id="nmap",
        name="Nmap",
        category="port_scan",
        description="Network exploration and security auditing tool",
        check_cmd=["nmap", "--version"],
        install_cmds={
            "brew": "brew install nmap",
            "apt": "sudo apt install nmap"
        },
        requires_root=True,
        usage_template="nmap -sV -sC {target}"
    ),
    "masscan": Tool(
        id="masscan",
        name="Masscan",
        category="port_scan",
        description="Mass IP port scanner (fastest port scanner)",
        check_cmd=["masscan", "--version"],
        install_cmds={
            "brew": "brew install masscan",
            "apt": "sudo apt install masscan"
        },
        requires_root=True,
        usage_template="masscan -p1-65535 {target} --rate=10000"
    ),
    "naabu": Tool(
        id="naabu",
        name="Naabu",
        category="port_scan",
        description="Fast port scanner written in Go",
        check_cmd=["naabu", "-version"],
        install_cmds={
            "go": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        },
        usage_template="naabu -host {target}"
    ),

    # ==================== SEARCH ENGINE SCANNERS ====================
    "shodan": Tool(
        id="shodan",
        name="Shodan",
        category="search_engine",
        description="Search engine for Internet-connected devices",
        check_cmd=["shodan", "version"],
        install_cmds={
            "pip": "pip install shodan"
        },
        requires_api=True,
        api_keys=["SHODAN_API_KEY"],
        api_url="https://account.shodan.io",
        usage_template="shodan search hostname:{domain}"
    ),

    "zoomeye": Tool(
        id="zoomeye",
        name="ZoomEye",
        category="search_engine",
        description="Cyberspace search engine (China)",
        is_api_only=True,
        requires_api=True,
        api_keys=["ZOOMEYE_API_KEY"],
        api_url="https://www.zoomeye.org/profile",
        usage_template="API: https://api.zoomeye.org/host/search"
    ),
    "fofa": Tool(
        id="fofa",
        name="FOFA",
        category="search_engine",
        description="Cyberspace search engine (China)",
        is_api_only=True,
        requires_api=True,
        api_keys=["FOFA_EMAIL", "FOFA_KEY"],
        api_url="https://en.fofa.info",
        usage_template="API: https://fofa.info/api"
    ),
    "securitytrails": Tool(
        id="securitytrails",
        name="SecurityTrails",
        category="search_engine",
        description="Historical DNS and domain data",
        is_api_only=True,
        requires_api=True,
        api_keys=["SECURITYTRAILS_KEY"],
        api_url="https://securitytrails.com/app/account",
        usage_template="API: https://api.securitytrails.com/v1/"
    ),

    # ==================== URL / ASSET DISCOVERY ====================
    "waybackurls": Tool(
        id="waybackurls",
        name="Waybackurls",
        category="url_discovery",
        description="Fetch URLs from the Wayback Machine",
        check_cmd=["waybackurls", "-h"],
        install_cmds={
            "go": "go install -v github.com/tomnomnom/waybackurls@latest"
        },
        usage_template="echo {domain} | waybackurls"
    ),
    "gau": Tool(
        id="gau",
        name="GAU",
        category="url_discovery",
        description="GetAllURLs - Fetch known URLs from multiple sources",
        check_cmd=["gau", "-version"],
        install_cmds={
            "go": "go install -v github.com/lc/gau/v2/cmd/gau@latest"
        },
        usage_template="echo {domain} | gau"
    ),
    "hakrawler": Tool(
        id="hakrawler",
        name="Hakrawler",
        category="url_discovery",
        description="Fast web crawler for gathering URLs and endpoints",
        check_cmd=["hakrawler", "-h"],
        install_cmds={
            "go": "go install -v github.com/hakluke/hakrawler@latest"
        },
        usage_template="echo {url} | hakrawler"
    ),
    "katana": Tool(
        id="katana",
        name="Katana",
        category="url_discovery",
        description="Next-generation crawling and spidering framework",
        check_cmd=["katana", "-version"],
        install_cmds={
            "go": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
        },
        usage_template="katana -u {url}"
    ),

    "jsfinder": Tool(
        id="jsfinder",
        name="JSFinder",
        category="url_discovery",
        description="Find URLs and subdomains from JS files",
        check_cmd=["python3", "-c", "import jsfinder"],
        install_cmds={
            "git": "git clone https://github.com/AzR919/JSFinder.git"
        },
        usage_template="python JSFinder.py -u {url}"
    ),

    # ==================== RECON FRAMEWORKS ====================

    "osmedeus": Tool(
        id="osmedeus",
        name="Osmedeus",
        category="framework",
        description="Fully automated offensive security framework",
        check_cmd=["osmedeus", "version"],
        install_cmds={
            "go": "go install -v github.com/j3ssie/osmedeus@latest"
        },
        usage_template="osmedeus scan -t {domain}"
    ),

}


def get_tools_by_category() -> Dict[str, List[Tool]]:
    """Group all tools by their category."""
    grouped = {}
    for tool_id, tool in TOOLS.items():
        cat = tool.category
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(tool)
    return grouped


def get_api_required_tools() -> List[Tool]:
    """Get all tools that require API keys."""
    return [t for t in TOOLS.values() if t.requires_api]


def get_all_required_api_keys() -> Dict[str, Dict[str, Any]]:
    """Get all unique API key requirements with their details."""
    keys = {}
    for tool in TOOLS.values():
        if tool.requires_api and tool.api_keys:
            for key in tool.api_keys:
                if key not in keys:
                    keys[key] = {
                        "tools": [],
                        "url": tool.api_url
                    }
                keys[key]["tools"].append(tool.name)
    return keys


def get_tool(tool_id: str) -> Optional[Tool]:
    """Get a specific tool by ID."""
    return TOOLS.get(tool_id)
