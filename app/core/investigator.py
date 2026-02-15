import asyncio
import os
import json
import re
import socket
import subprocess
import shlex
from typing import Dict, Any, List

async def run_cmd(cmd: str, timeout: int = 30) -> str:
    """Run a shell command asynchronously and return the output."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (stdout.decode() + stderr.decode()).strip()
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except:
                pass
            return "[!] Command timed out"
    except Exception as e:
        return f"[!] Error running command: {str(e)}"

async def get_whois(ip: str) -> Dict[str, Any]:
    # SECURITY FIX: Use list-based subprocess instead of shell=True to prevent command injection
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = (stdout.decode() + stderr.decode()).strip()
    except Exception as e:
        return {"raw": f"[!] WHOIS failed: {str(e)}", "owner": "Unknown", "netblock": "Unknown", "asn": "Unknown", "organization": "Unknown"}

    owner, asn, organization = "Unknown", "Unknown", "Unknown"
    netblocks = []

    for line in output.splitlines():
        line_strip = line.strip()
        if not line_strip or line_strip.startswith("%") or line_strip.startswith("#"):
            continue

        line_lower = line_strip.lower()
        if "orgname:" in line_lower or "descr:" in line_lower:
            name = line_strip.split(":", 1)[1].strip()
            if owner == "Unknown": owner = name
        if "cidr:" in line_lower or "inetnum:" in line_lower:
            block = line_strip.split(":", 1)[1].strip()
            if block not in netblocks: netblocks.append(block)
        if "originas:" in line_lower or "aut-num:" in line_lower:
            asn = line_strip.split(":", 1)[1].strip()
        if "organization:" in line_lower and organization == "Unknown":
            organization = line_strip.split(":", 1)[1].strip()

    return {
        "raw": output,
        "owner": owner,
        "netblock": ", ".join(netblocks) if netblocks else "Unknown",
        "asn": asn,
        "organization": organization
    }

async def get_dns_info(ip: str) -> Dict[str, Any]:
    # SECURITY FIX: Use list-based subprocess calls to prevent command injection
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "-x", ip, "+short",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        ptr = stdout.decode().strip() or "No PTR record"
    except:
        ptr = "No PTR record"
    
    try:
        proc = await asyncio.create_subprocess_exec(
            "nslookup", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        nslookup = (stdout.decode() + stderr.decode()).strip()
    except:
        nslookup = "nslookup failed"
    
    return {
        "ptr": ptr,
        "nslookup": nslookup
    }

async def run_nmap(ip: str, ports: List[int] = None) -> Dict[str, Any]:
    # SECURITY FIX: Use list-based subprocess to prevent command injection on IP/ports
    cmd = ["nmap", "-sS", "-sV", "-Pn"]
    
    if ports:
        port_arg = ",".join(str(p) for p in ports)
        cmd.extend(["-p", port_arg])
    else:
        cmd.extend(["--top-ports", "100"])
    
    cmd.append(ip)
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = (stdout.decode() + stderr.decode()).strip()
    except Exception as e:
        output = f"[!] Nmap failed: {str(e)}"
    
    return {
        "raw": output
    }

async def get_curl_headers(ip: str, port: int) -> Dict[str, Any]:
    protocol = "https" if port == 443 else "http"
    output = await run_cmd(f"curl -Iks {protocol}://{ip}:{port}")
    return {
        "raw": output
    }

async def get_ssl_details(ip: str, port: int = 443) -> Dict[str, Any]:
    if port != 443: return {}
    output = await run_cmd(f"echo | openssl s_client -connect {ip}:443 -brief", timeout=10)
    return {
        "raw": output
    }

async def check_mongodb_nc(ip: str) -> str:
    """Specialized check for MongoDB using Netcat."""
    # nc -vz <IP> 27017
    output = await run_cmd(f"nc -vz -w 3 {ip} 27017")
    if "succeeded" in output.lower() or "open" in output.lower():
        return f"[!] MongoDB (27017) is OPEN (nc verified)"
    return None

async def check_exposures(ip: str) -> List[str]:
    exposures = []
    
    # Check MongoDB with nc if explicitly requested
    mongo_nc = await check_mongodb_nc(ip)
    if mongo_nc:
        exposures.append(mongo_nc)

    # Simple socket check for common DB ports
    common_db_ports = {
        27017: "MongoDB",
        6379: "Redis",
        3306: "MySQL",
        5432: "PostgreSQL",
        21: "FTP",
        22: "SSH",
        23: "Telnet"
    }
    
    for port, name in common_db_ports.items():
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
            exposures.append(f"{name} ({port}) is OPEN")
            writer.close()
            await writer.wait_closed()
        except:
            pass
            
    return exposures

async def investigate_ip(ip: str, ports: List[int]) -> Dict[str, Any]:
    """Unified entry point for deep investigation of an IP."""
    # Run all checks concurrently
    tasks = [
        get_whois(ip),
        get_dns_info(ip),
        run_nmap(ip, ports),
        check_exposures(ip)
    ]
    
    # Add port-specific tasks
    for port in ports:
        if port != 27017:
            tasks.append(get_curl_headers(ip, port))
        else:
            # Placeholder for Mongo to avoid NoneType errors
            async def get_empty(): return {}
            tasks.append(get_empty()) 
            
        if port == 443:
            tasks.append(get_ssl_details(ip))
            
    results = await asyncio.gather(*tasks)
    
    final_data = {
        "whois": results[0],
        "dns": results[1],
        "nmap": results[2],
        "exposures": results[3],
        "port_data": {}
    }
    
    # Distribute results
    idx = 4
    for port in ports:
        final_data["port_data"][port] = {
            "curl": results[idx]
        }
        idx += 1
        if port == 443:
            final_data["port_data"][port]["ssl"] = results[idx]
            idx += 1
            
    return final_data
