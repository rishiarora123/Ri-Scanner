import asyncio
import os
import socket
import json
import time
import subprocess
import ipaddress
from typing import List, Dict, Any, Set, Optional
from .recon_runner import get_recon_runner
from .subdomain_manager import get_subdomain_manager
from .utils import get_ip_info, resolve_asn_to_ips, analyze_service
from .investigator import investigate_ip

# ── Shared State ──────────────────────────────────────────────────
# These are set by routes.py at import time via set_shared_state()
_scan_status = None
_scan_logs = None

def set_shared_state(status_dict, logs_list):
    """Called by routes.py to share the in-memory dicts instead of HTTP calls."""
    global _scan_status, _scan_logs
    _scan_status = status_dict
    _scan_logs = logs_list

def update_status(data):
    """Update scan status via shared dict (no HTTP overhead)."""
    if _scan_status is not None:
        for k, v in data.items():
            _scan_status[k] = v

def log_event(message):
    """Log to console + shared list (no HTTP overhead)."""
    print(message)
    if _scan_logs is not None:
        _scan_logs.append(message)
        if len(_scan_logs) > 500:
            _scan_logs.pop(0)

def _is_stopped(scan_context):
    """Check if scan has been requested to stop."""
    if scan_context and scan_context.get("stop_event"):
        return scan_context["stop_event"].is_set()
    return False

# ── Helpers ───────────────────────────────────────────────────────

async def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """Resolve a domain to an IP address."""
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, domain)
    except Exception:
        return None

# ── Main Scan Logic ───────────────────────────────────────────────

async def run_scan_logic(mode, target, threads=10, ports="80,443", masscan_rate=10000, scan_context=None):
    """
    Main logic for Ri-Scanner Pro.
    Flow:
    1. Entry Point Handling:
       - Domain (recon): Discovery -> ASN extraction -> IP extraction
       - ASN List: ASN resolution -> IP extraction
       - IP File: Direct extraction
    2. Parallel Scan IP Ranges for ports 80, 443 (Masscan, Naabu)
    """
    all_ip_ranges = []
    
    # Shared state for parallel scanning
    discovered_findings = set()
    db_lock = asyncio.Lock()
    manager = get_subdomain_manager()
    db = manager.db
    m_semaphore = asyncio.Semaphore(threads)
    n_semaphore = asyncio.Semaphore(threads)
    
    # Progress trackers
    m_done_count = 0
    n_done_count = 0
    tracker_lock = asyncio.Lock()
    investigate_semaphore = asyncio.Semaphore(20)  # Max 20 concurrent deep investigations
    
    log_event(f"[*] Initializing scan logic with parallel threads: {threads}")
    
    # ── STOP CHECK ──
    if _is_stopped(scan_context):
        log_event("[!] Scan stopped before start.")
        update_status({"phase": "Idle"})
        return
    
    if mode == "recon":
        log_event(f"🚀 Starting Deep Infra Analysis for Domain: {target}")
        update_status({"active_threads": threads})
        
        # 1. SUBDOMAIN DISCOVERY
        log_event("🔍 Phase 1: Subdomain Discovery (Chaos, Subfinder, Assetfinder)")
        update_status({"phase": "🔍 Discovery (Subdomains)"})
        runner = get_recon_runner()
        discovery_results = await runner.run_subdomain_recon(target, tools=["chaos", "subfinder", "assetfinder"])
        subdomains = discovery_results.get("subdomains", [])
        
        if not subdomains:
            log_event("[!] No subdomains found. Using main domain for further jobs.")
            subdomains = [target]
        
        # ── STOP CHECK ──
        if _is_stopped(scan_context):
            log_event("[!] Scan stopped after subdomain discovery.")
            update_status({"phase": "Stopped"})
            return
        
        # 2. ASN EXTRACTION & IP RANGE RESOLUTION
        log_event("🌏 Phase 2: ASN Extraction & IP Range Discovery")
        update_status({"phase": "🌏 Extracting ASNs & IP Ranges"})
        asns = set()
        for sub in subdomains:
            if _is_stopped(scan_context):
                break
            ip = await resolve_domain_to_ip(sub)
            if ip:
                info = get_ip_info(ip)
                asn = info.get("asn")
                if asn and asn != "Unknown":
                    asns.add(asn)
        
        if _is_stopped(scan_context):
            log_event("[!] Scan stopped during ASN extraction.")
            update_status({"phase": "Stopped"})
            return
        
        log_event(f"[*] Found unique ASNs: {', '.join(asns)}")
        for asn in asns:
            ranges = resolve_asn_to_ips(asn)
            # Filter for IPv4 only
            for r in ranges:
                try:
                    if "/" in r:
                        if ipaddress.ip_network(r, strict=False).version == 4:
                            all_ip_ranges.append(r)
                    elif ipaddress.ip_address(r).version == 4:
                        all_ip_ranges.append(r)
                except: continue
            
    elif mode == "asn_list":
        log_event(f"🚀 Starting ASN List Scan: {target}")
        update_status({"active_threads": threads, "phase": "🌏 Resolving ASNs"})
        asn_list = [a.strip() for a in target.split(",")]
        for asn in asn_list:
            if _is_stopped(scan_context):
                break
            if asn.upper().startswith("AS"): asn = asn[2:]
            ranges = resolve_asn_to_ips(asn)
            for r in ranges:
                try:
                    if "/" in r:
                        if ipaddress.ip_network(r, strict=False).version == 4:
                            all_ip_ranges.append(r)
                    elif ipaddress.ip_address(r).version == 4:
                        all_ip_ranges.append(r)
                except: continue
            
    elif mode == "ip_file":
        log_event(f"🚀 Starting IP File Scan: {target}")
        update_status({"active_threads": threads, "phase": "📡 Reading IP Ranges"})
        if os.path.exists(target):
            with open(target, "r") as f:
                for line in f:
                    r = line.strip()
                    if r:
                        try:
                            if "/" in r:
                                if ipaddress.ip_network(r, strict=False).version == 4:
                                    all_ip_ranges.append(r)
                            elif ipaddress.ip_address(r).version == 4:
                                all_ip_ranges.append(r)
                        except: continue
    
    # ── STOP CHECK ──
    if _is_stopped(scan_context):
        log_event("[!] Scan stopped before scanning phase.")
        update_status({"phase": "Stopped"})
        return
    
    # Consolidated range cleanup + CIDR deduplication
    all_ip_ranges = _deduplicate_cidrs(list(set(all_ip_ranges)))
    log_event(f"[*] Initialized {len(all_ip_ranges)} total IP ranges for scanning (after dedup).")
    
    if not all_ip_ranges:
        log_event("[!] No IP ranges identified. Scan cannot proceed.")
        update_status({"phase": "Idle"})
        return

    # Write final ranges to a temp file for masscan
    if not os.path.exists("Tmp"): os.makedirs("Tmp")
    range_file = os.path.join("Tmp", f"ranges_{int(time.time())}.txt")
    with open(range_file, "w") as f:
        f.write("\n".join(all_ip_ranges))

    # 3. IP SCANNING (Masscan & Naabu)
    log_event(f"📡 Phase 3: Infrastructure Scanning ({ports}) with {threads} threads")
    
    # Split ranges into chunks
    chunks = []
    chunk_size = max(1, len(all_ip_ranges) // threads)
    for i in range(0, len(all_ip_ranges), chunk_size):
        chunks.append(all_ip_ranges[i:i + chunk_size])
    
    update_status({
        "phase": "📡 Scanning (Parallel)", 
        "masscan_total": len(chunks), 
        "masscan_progress": 0,
        "masscan_ranges_total": len(chunks),
        "masscan_ranges_done": 0,
        "naabu_total": len(chunks), 
        "naabu_progress": 0
    })
    
    # Segregate port 27017
    port_list = [p.strip() for p in ports.split(",")]
    has_mongo = "27017" in port_list
    clean_ports = ",".join([p for p in port_list if p != "27017"])
    
    # Result collection
    m_files = []
    n_files = []
    nc_findings = []
    m_lock = asyncio.Lock()
    n_lock = asyncio.Lock()
    nc_lock = asyncio.Lock()
    nc_semaphore_200 = asyncio.Semaphore(200)  # Reduced from 1000 to 200
    discovery_lock = asyncio.Lock()
    live_tasks = set()  # Track background tasks to prevent early exit
    
    # Dedicated discovery file for 27017
    nc_discovery_file = os.path.join("Tmp", f"mongo_findings_{int(time.time())}.txt")
    if has_mongo:
        log_event(f"[*] Persistent discovery file initialized: {nc_discovery_file}")
    
    async def process_investigation(ip, ports):
        if _is_stopped(scan_context):
            return
        try:
            async with investigate_semaphore:
                # Ensure db is available (refresh from manager)
                curr_db = manager.db if manager.db is not None else db

                log_event(f"[*] Deep Investigation: {ip}...")
                # 1. Basic Web/SSL Analysis (fast)
                service_results = {}
                loop = asyncio.get_running_loop()
                for p in ports:
                    if _is_stopped(scan_context):
                        return
                    try:
                        service_results[p] = await loop.run_in_executor(None, analyze_service, ip, p)
                    except: service_results[p] = {}
                
                # 2. Multi-Tool Analysis (Whois, Nmap, DNS, etc.)
                try:
                    deep_info = await investigate_ip(ip, ports)
                except Exception as e:
                    log_event(f"[!] Investigation failed for {ip}: {e}")
                    deep_info = {"port_data": {}, "whois": {}, "dns": {}, "nmap": {}, "exposures": []}
                
                ip_info = get_ip_info(ip)
                
                # Final document assembly
                for p in ports:
                    s_info = service_results.get(p) or {}
                    d_info = (deep_info.get("port_data") or {}).get(p) or {}
                    
                    doc = {
                        "scan_id": target, "ip": ip, "port": p,
                        "protocol": "mongodb" if p == 27017 else ("https" if p == 443 else "http"),
                        "domain": s_info.get("domain") or "N/A",
                        "ssl_cn": s_info.get("ssl_cn"),
                        "title": s_info.get("title") or ("MongoDB Discovery" if p == 27017 else "No Title"),
                        "status_code": s_info.get("status_code"),
                        "technologies": s_info.get("technologies") or (["MongoDB"] if p == 27017 else []),
                        "response_headers": s_info.get("headers") or {},
                        "request": s_info.get("request") or s_info.get("url") or (f"mongodb://{ip}:{p}" if p == 27017 else f"http://{ip}:{p}"),
                        "asn": ip_info.get("asn"), "org": ip_info.get("org"),
                        "country": ip_info.get("country"),
                        # Deep Investigation Data
                        "whois": deep_info.get("whois"),
                        "dns": deep_info.get("dns"),
                        "nmap": deep_info.get("nmap"),
                        "exposures": deep_info.get("exposures"),
                        "curl_raw": (d_info.get("curl") or {}).get("raw") if isinstance(d_info.get("curl"), dict) else None,
                        "ssl_raw": (d_info.get("ssl") or {}).get("raw") if isinstance(d_info.get("ssl"), dict) else None,
                        "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "source": "infra_scan"
                    }
                    if curr_db is not None:
                        try:
                            curr_db.extraction_results.update_one(
                                {"scan_id": target, "ip": ip, "port": p},
                                {"$set": doc}, upsert=True
                            )
                            # Confirm success for Mongo
                            if p == 27017:
                                log_event(f"✅ [NC] SUCCESS: Data for {ip}:27017 saved to DB.")
                        except Exception as dbe:
                            log_event(f"[!] DB Error saving {ip}:{p}: {dbe}")
                    else:
                        log_event(f"[!] DB Error: manager.db is None for {ip}")
                
                async with discovery_lock:
                    update_status({"found_count": len(discovered_findings)})
        except Exception as e:
            log_event(f"[!] Critical error in investigation task for {ip}: {e}")
        finally:
            # Self-remove from live tasks if tracked
            task = asyncio.current_task()
            if task in live_tasks:
                live_tasks.remove(task)

    async def run_nc_on_ip(ip):
        """Single NC check with 5s timeout as requested."""
        if _is_stopped(scan_context):
            return
        try:
            # -w 5 for 5 seconds timeout
            cmd = f"nc -vz -w 5 {ip} 27017"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                log_event(f"🔥 [+] [NC] DISCOVERY: Found Open 27017 on {ip} (Added to Queue)")
                # Append to txt file immediately as requested
                try:
                    with open(nc_discovery_file, "a") as af:
                        af.write(f"{ip}\n")
                except: pass

                async with discovery_lock:
                    if (ip, 27017) not in discovered_findings:
                        discovered_findings.add((ip, 27017))
                        # Trigger deep investigation immediately in background
                        t = asyncio.create_task(process_investigation(ip, [27017]))
                        live_tasks.add(t)
                        t.add_done_callback(lambda x: live_tasks.discard(x))
                        
                async with nc_lock:
                    nc_findings.append((ip, 27017))
        except:
            pass

    async def run_nc_chunk(idx, chunk):
        """Run NC checks with CIDR expansion using a memory-efficient worker pattern."""
        log_event(f"[*] Starting specialized NC scan on chunk {idx} (Streaming Expansion, 200 Concurrency)")
        
        queue = asyncio.Queue(maxsize=2000)
        WORKER_COUNT = 200  # Reduced from 1000 for stability
        
        async def loader():
            for range_str in chunk:
                if _is_stopped(scan_context):
                    break
                try:
                    if "/" in range_str:
                        network = ipaddress.ip_network(range_str, strict=False)
                        for ip in network:
                            if _is_stopped(scan_context):
                                break
                            await queue.put(str(ip))
                    else:
                        await queue.put(range_str)
                except: continue
            # Signal workers to exit
            for _ in range(WORKER_COUNT): await queue.put(None)

        async def worker():
            while True:
                ip = await queue.get()
                if ip is None: break
                if _is_stopped(scan_context):
                    queue.task_done()
                    break
                async with nc_semaphore_200:
                    await run_nc_on_ip(ip)
                queue.task_done()

        # Run loader and workers
        workers = [asyncio.create_task(worker()) for _ in range(WORKER_COUNT)]
        await loader()
        await asyncio.gather(*workers)
        return True

    async def run_masscan_chunk(idx, chunk):
        try:
            if not clean_ports: return True
            if _is_stopped(scan_context): return True
            async with m_semaphore:
                chunk_file = os.path.join("Tmp", f"masscan_chunk_{idx}_{int(time.time())}.txt")
                output_file = chunk_file + ".json"
                try:
                    with open(chunk_file, "w") as f:
                        f.write("\n".join(chunk))
                    
                    log_event(f"[*] Starting Masscan on chunk {idx} ({len(chunk)} targets) for ports: {clean_ports}")
                    cmd = f"sudo masscan -p{clean_ports} -iL {chunk_file} --rate {masscan_rate} -oJ {output_file} --wait 0"
                    proc = await asyncio.create_subprocess_shell(cmd)
                    await proc.communicate()
                    
                    if os.path.exists(output_file):
                        async with m_lock:
                            m_files.append(output_file)
                finally:
                    if os.path.exists(chunk_file): os.remove(chunk_file)
        finally:
            # Update progress even if skipped or failed
            async with tracker_lock:
                nonlocal m_done_count
                m_done_count += 1
                update_status({
                    "masscan_progress": m_done_count,
                    "masscan_ranges_done": m_done_count
                })
        return True

    async def run_naabu_chunk(idx, chunk):
        try:
            if not clean_ports: return True
            if _is_stopped(scan_context): return True
            async with n_semaphore:
                chunk_file = os.path.join("Tmp", f"naabu_chunk_{idx}_{int(time.time())}.txt")
                output_file = chunk_file + ".txt"
                try:
                    with open(chunk_file, "w") as f:
                        f.write("\n".join(chunk))
                    
                    log_event(f"[*] Starting Naabu on chunk {idx} ({len(chunk)} targets) for ports: {clean_ports}")
                    cmd = f"naabu -list {chunk_file} -p {clean_ports} -silent -o {output_file}"
                    proc = await asyncio.create_subprocess_shell(cmd)
                    await proc.communicate()
                    
                    if os.path.exists(output_file):
                        async with n_lock:
                            n_files.append(output_file)
                finally:
                    if os.path.exists(chunk_file): os.remove(chunk_file)
        finally:
            async with tracker_lock:
                nonlocal n_done_count
                n_done_count += 1
                update_status({"naabu_progress": n_done_count})
        return True

    async def scan_chunk(idx, chunk):
        if _is_stopped(scan_context):
            return
        tasks = [
            run_masscan_chunk(idx, chunk),
            run_naabu_chunk(idx, chunk)
        ]
        if has_mongo:
            tasks.append(run_nc_chunk(idx, chunk))
        await asyncio.gather(*tasks)

    # Launch all chunks
    try:
        await asyncio.gather(*(scan_chunk(i, c) for i, c in enumerate(chunks)))
    finally:
        if os.path.exists(range_file): 
            try: os.remove(range_file)
            except: pass

    # ── STOP CHECK ──
    if _is_stopped(scan_context):
        log_event("[!] Scan stopped. Partial results may be available.")
        update_status({"phase": "Stopped"})
        return

    log_event("[+] Scanning phase completed. Consolidating results...")
    update_status({"phase": "📊 Consolidating & Extracting"})
    
    # Consolidation and Bulk Storage
    masscan_combined_file = os.path.join("Tmp", f"masscan_combined_{int(time.time())}.json")
    naabu_combined_file = os.path.join("Tmp", f"naabu_combined_{int(time.time())}.txt")
    
    all_findings_list = []
    all_findings_list.extend(nc_findings)
    
    # Merge Masscan
    masscan_all_entries = []
    for f_path in m_files:
        try:
            with open(f_path, "r") as f:
                data = json.load(f)
                masscan_all_entries.extend(data)
                for entry in data:
                    ip = entry.get("ip")
                    for p in entry.get("ports", []):
                        all_findings_list.append((ip, p.get("port")))
            os.remove(f_path)
        except: pass
    
    with open(masscan_combined_file, "w") as f:
        json.dump(masscan_all_entries, f)
        
    # Merge Naabu
    with open(naabu_combined_file, "w") as combined_f:
        for f_path in n_files:
            try:
                with open(f_path, "r") as f:
                    for line in f:
                        combined_f.write(line)
                        if ":" in line:
                            ip, port = line.strip().split(":")
                            all_findings_list.append((ip, int(port)))
                os.remove(f_path)
            except: pass

    # Combined deduplication and IP collection for deep analysis
    ip_to_ports = {}
    for ip, port in all_findings_list:
        async with discovery_lock:
            if (ip, port) not in discovered_findings:
                discovered_findings.add((ip, port))
                if ip not in ip_to_ports: ip_to_ports[ip] = []
                ip_to_ports[ip].append(port)

    # ── STOP CHECK ──
    if _is_stopped(scan_context):
        log_event("[!] Scan stopped before deep investigation phase.")
        update_status({"phase": "Stopped"})
        return

    # Run remaining investigations and wait for all background tasks
    investigation_tasks = []
    for ip, ports_list in ip_to_ports.items():
        if _is_stopped(scan_context):
            break
        investigation_tasks.append(process_investigation(ip, ports_list))
    
    if investigation_tasks or live_tasks:
        log_event(f"[*] Finalizing {len(investigation_tasks) + len(live_tasks)} deep investigation tasks...")
        # Combine remaining explicit tasks and already running background tasks
        all_pending = list(live_tasks) + [asyncio.create_task(t) for t in investigation_tasks]
        if all_pending:
            await asyncio.gather(*all_pending)

    # Final summary in logs
    if nc_findings:
        log_event(f"[*] Discovery Summary: Found {len(nc_findings)} IPs with Port 27017 open.")
        for ip, p in nc_findings:
            log_event(f"  > Found: {ip}:{p}")

    log_event(f"✅ Deep Infra Analysis Completed. Total unique discoveries: {len(discovered_findings)}")
    log_event(f"[*] Combined results available in Tmp: {masscan_combined_file}, {naabu_combined_file}")
    
    # Cleanup combined files (respect keep_files flag)
    keep = scan_context.get("keep_files", False) if scan_context else False
    if not keep:
        try:
            os.remove(masscan_combined_file)
            os.remove(naabu_combined_file)
        except: pass
    else:
        log_event(f"[*] Keeping result files: {masscan_combined_file}, {naabu_combined_file}")
    
    update_status({"phase": "Idle"})

# ── CIDR Deduplication ────────────────────────────────────────────

def _deduplicate_cidrs(ranges):
    """Merge overlapping/contained CIDR ranges to minimize scan targets."""
    if not ranges:
        return ranges
    try:
        networks = []
        for r in ranges:
            try:
                networks.append(ipaddress.ip_network(r, strict=False))
            except:
                continue
        
        # Sort by network address then by prefix length (largest first)
        networks.sort(key=lambda n: (n.network_address, n.prefixlen))
        
        merged = []
        for net in networks:
            # Check if this network is already contained in a previous one
            is_contained = False
            for existing in merged:
                if net.subnet_of(existing):
                    is_contained = True
                    break
            if not is_contained:
                merged.append(net)
        
        result = [str(n) for n in merged]
        if len(result) < len(ranges):
            print(f"[*] CIDR dedup: {len(ranges)} → {len(result)} ranges ({len(ranges) - len(result)} removed)")
        return result
    except Exception as e:
        print(f"[!] CIDR dedup failed: {e}, using original ranges")
        return ranges
