"""
Ri-Scanner Pro - Cleaned Recon Tools Configuration
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

@dataclass
class Tool:
    """Represents a reconnaissance tool."""
    id: str
    name: str
    category: str
    description: str
    check_cmd: Optional[List[str]] = None
    install_cmds: Dict[str, str] = field(default_factory=dict)
    requires_api: bool = False
    api_keys: List[str] = field(default_factory=list)
    api_url: Optional[str] = None
    usage_template: Optional[str] = None
    requires_root: bool = False
    is_api_only: bool = False

TOOLS: Dict[str, Tool] = {
    "subfinder": Tool(
        id="subfinder",
        name="Subfinder",
        category="subdomain",
        description="Fast passive subdomain enumeration tool",
        check_cmd=["subfinder", "-version"],
        install_cmds={
            "go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "brew": "brew install subfinder"
        },
        usage_template="subfinder -d {domain} -silent"
    ),
    "assetfinder": Tool(
        id="assetfinder",
        name="Assetfinder",
        category="subdomain",
        description="Find domains and subdomains related to a given domain",
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
        description="Chaos dataset for subdomain discovery",
        check_cmd=["chaos", "-version"],
        install_cmds={
            "go": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        },
        requires_api=True,
        api_keys=["CHAOS_API_KEY"],
        api_url="https://chaos.projectdiscovery.io",
        usage_template="chaos -d {domain} -silent"
    ),
    "masscan": Tool(
        id="masscan",
        name="Masscan",
        category="port_scan",
        description="Fastest port scanner",
        check_cmd=["masscan", "--version"],
        install_cmds={
            "brew": "brew install masscan",
            "apt": "sudo apt install masscan"
        },
        requires_root=True,
        usage_template="masscan -p80,443 {target} --rate={rate} -oL {output}"
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
        usage_template="naabu -host {target} -p 80,443 -silent"
    ),
    "ffuf": Tool(
        id="ffuf",
        name="Ffuf",
        category="fuzzing",
        description="Fast web fuzzer written in Go",
        check_cmd=["ffuf", "-version"],
        install_cmds={
            "go": "go install github.com/ffuf/ffuf/v2@latest",
            "brew": "brew install ffuf"
        },
        usage_template="ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403 -o {output} -of json -t 50"
    ),
    "katana": Tool(
        id="katana",
        name="Katana",
        category="crawling",
        description="Next-generation crawling and spidering framework",
        check_cmd=["katana", "-version"],
        install_cmds={
            "go": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "brew": "brew install katana"
        },
        usage_template="katana -u {url} -silent -json -o {output}"
    )
}

def get_tools_by_category() -> Dict[str, List[Tool]]:
    grouped = {}
    for tool in TOOLS.values():
        cat = tool.category
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(tool)
    return grouped

def get_tool(tool_id: str) -> Optional[Tool]:
    return TOOLS.get(tool_id)
