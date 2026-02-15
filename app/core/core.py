import asyncio
import os
import socket
import json
import time
import subprocess
import ipaddress
import threading  # FIX: Added for phase-gate Events
from typing import List, Dict, Any, Set, Optional
from .recon_runner import get_recon_runner
from .subdomain_manager import get_subdomain_manager
from .utils import get_ip_info, resolve_asn_to_ips, analyze_service
from .investigator import investigate_ip
from .advanced_recon import SubdomainDiscovery, SubdomainIntelligence, EndpointMapper
from .recon_progress import RealtimeScanTracker, ScanPhase, StructuredResultsCompiler

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

def _wait_for_user_gate(scan_context, gate_name, phase_complete_name, next_phase_name):
    """
    FIX: Phase-gate helper — blocks the scan thread until the user confirms
    continuation via the /continue_scan API, or until stop is requested.
    
    The gate is a threading.Event in scan_context. The /continue_scan route
    sets it when the user clicks "Continue" on the Dashboard.
    
    Returns:
        True if user chose to continue
        False if stop was requested while waiting
    """
    gate = scan_context.get(gate_name) if scan_context else None
    if gate is None:
        return True  # No gate configured — auto-continue (non-recon modes)
    
    log_event(f"⏸️ {phase_complete_name} complete. Waiting for user to confirm {next_phase_name}...")
    update_status({
        "phase": f"⏸️ {phase_complete_name} — Waiting for user",
        "waiting_for_user": True,
        "current_gate": gate_name,
        "next_phase": next_phase_name,
    })
    
    # Block until gate is set (user clicks Continue) or stop is requested
    while not gate.is_set():
        if _is_stopped(scan_context):
            log_event(f"[!] Scan stopped while waiting at {gate_name}.")
            update_status({"phase": "Stopped", "waiting_for_user": False})
            return False
        gate.wait(timeout=0.5)  # Check stop_event every 500ms
    
    log_event(f"▶️ User confirmed. Proceeding to {next_phase_name}.")
    update_status({"waiting_for_user": False, "current_gate": None})
    return True

def _is_private_or_reserved(ip_range: str) -> bool:
    """
    SECURITY: Check if IP/CIDR is in private, loopback, or reserved ranges.
    Prevents accidental scanning of internal infrastructure.
    
    Args:
        ip_range: Single IP or CIDR block
    
    Returns:
        True if IP/CIDR is private or reserved
    """
    try:
        if "/" in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            return (network.is_private or network.is_loopback or 
                    network.is_link_local or network.is_reserved)
        else:
            addr = ipaddress.ip_address(ip_range)
            return (addr.is_private or addr.is_loopback or 
                    addr.is_link_local or addr.is_reserved)
    except (ValueError, TypeError):
        # Invalid IP format - let it pass, will fail later with better error
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
        log_event(f"🚀 Starting Advanced 4-Phase Recon for Domain: {target}")
        update_status({"active_threads": threads, "phase": "Initializing Pipeline..."})

        # Initialize progress tracker (UI Bridge)
        tracker = RealtimeScanTracker(on_update=update_status)
        tracker.set_phase(ScanPhase.DISCOVERY)

        # ── PHASE 1: SUBDOMAIN DISCOVERY (MANDATORY) ──────────────────────
        log_event(f"🔍 [Phase 1] Subdomain Discovery (Chaos, Subfinder, Assetfinder)")
        update_status({"phase": "🔍 Phase 1: Subdomain Discovery"})

        # FIX: Pass log/status callbacks so Phase 1 can report per-tool progress
        discovery = SubdomainDiscovery(log_fn=log_event, status_fn=update_status)
        # Run all discovery tools and merge results
        discovery_results = await discovery.discover_all(target)
        
        all_subdomains = list(discovery_results.get("subdomains", []))
        live_subdomains = discovery_results.get("live_subdomains", []) # List of dicts {domain, ip, ...}
        
        # UI Update
        tracker.update_discovery(
            total=len(all_subdomains),
            live=len(live_subdomains),
            dead=discovery_results.get("dead_count", 0)
        )
        
        log_event(f"[*] Discovery complete: {len(all_subdomains)} total, {len(live_subdomains)} live.")

        # Save base subdomains to DB — these appear in the Websites tab immediately
        try:
            manager.save_subdomains(scan_id=target, subdomains=all_subdomains, source="combined_recon")
        except Exception as e:
            log_event(f"[!] Failed to save subdomains to DB: {e}")

        if not all_subdomains:
             log_event("[!] No subdomains found. Using main domain.")
             all_subdomains = [target]

        # ── FIX: Push Phase 1 stats to scan_status for Dashboard display ──
        # This data drives the Dashboard UI: subdomain counts, tools used,
        # and the phase-gate prompt asking user whether to continue.
        update_status({
            "phase1_subdomains_total": len(all_subdomains),
            "phase1_live": len(live_subdomains),
            "phase1_dead": discovery_results.get("dead_count", 0),
            "phase1_tools_used": list(discovery_results.get("by_source", {}).keys()),
            "phase1_complete": True,
        })

        # ── FIX: PHASE GATE — DO NOT auto-continue to Phase 2 ─────────────
        # The scan thread blocks here until the user clicks "Continue" on
        # the Dashboard, or clicks "Stop & Export".
        if not _wait_for_user_gate(scan_context, "gate_phase2",
                                   "Phase 1 (Subdomain Discovery)",
                                   "Phase 2 (Intelligence & Mapping)"):
            return  # User chose to stop

        # ── STOP CHECK ────────────────────────────────────────────────────
        if _is_stopped(scan_context):
            return

        # ── PHASE 2: INTELLIGENCE & SURFACE MAPPING ───────────────────────
        log_event(f"🔬 [Phase 2] Subdomain Intelligence & Surface Mapping")
        tracker.set_phase(ScanPhase.INTELLIGENCE)
        
        intel_engine = SubdomainIntelligence()
        base_mapper = EndpointMapper()
        
        phase2_ips = set()
        
        # Parallel Execution for Intelligence Gathering
        # Use existing semaphore to limit concurrency
        async def process_subdomain(sub):
             if _is_stopped(scan_context): return
             
             # Identify IP - either from live_subdomains or resolve fresh
             ip = None
             # Check if we already have IP from discovery phase
             for live in live_subdomains:
                 if live["domain"] == sub:
                     ip = live.get("ip")
                     break
             
             if not ip:
                 ip = await resolve_domain_to_ip(sub)
             
             if not ip: 
                 # Subdomain inactive
                 return

             phase2_ips.add(ip)
             
             # 1. Gather Deep Intelligence
             # FIX: Log which subdomain is being scanned right now
             log_event(f"  🔬 Scanning: {sub} ({ip})")
             try:
                 intel_data = await intel_engine.gather_intelligence(sub, ip)
             except Exception as e:
                 # Fallback
                 intel_data = {"domain": sub, "primary_ip": ip, "error": str(e)}

             # 2. Surface Mapping (Crawling)
             # Only crawl if it's a web service
             is_web = intel_data.get("http_headers") or intel_data.get("technologies") or (intel_data.get("ssl_certificate") and intel_data.get("ssl_certificate").get("valid"))
             
             # 3. Endpoint Discovery
             if is_web:
                 try:
                     crawl_data = await base_mapper.crawl_domain(sub)
                     if crawl_data and crawl_data.get("endpoints"):
                        intel_data["endpoints"] = crawl_data.get("endpoints")
                        
                     # JS Endpoints
                     js_endpoints = await base_mapper.extract_javascript_endpoints(sub)
                     if js_endpoints:
                         if "endpoints" not in intel_data: intel_data["endpoints"] = {}
                         intel_data["endpoints"]["javascript"] = js_endpoints
                 except: pass
             
             # Save to DB via Manager
             def _sanitize(obj):
                 if isinstance(obj, Exception): return str(obj)
                 if isinstance(obj, set): return list(obj)
                 if isinstance(obj, dict): return {k: _sanitize(v) for k, v in obj.items()}
                 if isinstance(obj, list): return [_sanitize(i) for i in obj]
                 return obj
                 
             manager.save_domain_details(scan_id=target, domain=sub, details=_sanitize(intel_data))
             
             # Update Progress (Internal tracker count)
             # We rely on outer loop to update tracker total/completed to avoid too many UI updates

        # Iterate and run
        # We need to run these concurrently but limited
        # Use the passed 'threads' argument for concurrency level
        
        chunk_size = threads * 2 
        processed_count = 0
        
        # Convert to list for slicing
        subs_list = list(all_subdomains)
        total_subs = len(subs_list)
        log_event(f"[*] Starting intelligence scan on {total_subs} subdomains...")
        
        # Use a semaphore to limit concurrency
        sem = asyncio.Semaphore(threads)
        processed_count = 0
        
        async def bound_process(sub):
            nonlocal processed_count
            async with sem:
                await process_subdomain(sub)
                processed_count += 1
                
                # Update UI row-by-row
                tracker.update_intelligence(total=total_subs, completed=processed_count)
                update_status({
                    "phase": f"🔬 Phase 2: Intelligence ({processed_count}/{total_subs})",
                    "phase2_completed": processed_count,
                    "phase2_total": total_subs,
                })

        # Run all tasks and wait
        tasks = [bound_process(s) for s in subs_list]
        await asyncio.gather(*tasks)

        log_event(f"  ✅ Intelligence: {processed_count}/{total_subs} subdomains scanned")

        # ── PHASE 3: REAL-TIME VISIBILITY (Is active throughout Phase 2) ──
        # Implemented via tracker updates above.

        # ── FIX: PHASE GATE — Pause after Phase 2, before Phase 4 (ASN) ──
        update_status({"phase2_complete": True})
        if not _wait_for_user_gate(scan_context, "gate_phase4",
                                   "Phase 2 (Intelligence & Mapping)",
                                   "Phase 4 (ASN Expansion)"):
            return  # User chose to stop
        
        # ── PHASE 4: ASN & INFRASTRUCTURE EXPANSION ───────────────────────
        if _is_stopped(scan_context): return

        log_event(f"🌏 [Phase 4] ASN & Infrastructure Expansion")
        tracker.set_phase(ScanPhase.ASN_EXPANSION)
        
        unique_asns = set()
        for ip in phase2_ips:
             try:
                 info = get_ip_info(ip)
                 if info and info.get("asn"):
                     asn_val = info["asn"]
                     if asn_val and asn_val != "Unknown":
                         unique_asns.add(asn_val)
             except: pass
        
        log_event(f"[*] Found {len(unique_asns)} unique ASNs from valid subdomains.")
        update_status({
            "phase": f"🌐 Phase 4: ASN Expansion ({len(unique_asns)} ASNs)",
            "phase4_asn_count": len(unique_asns),
        })
        
        hosts_found = 0
        expanded_ranges = []
        
        for idx, asn in enumerate(unique_asns):
             if _is_stopped(scan_context): break
             # FIX: Log per-ASN expansion progress
             log_event(f"  🌐 Expanding ASN {idx+1}/{len(unique_asns)}: {asn}")
             try:
                 asn_ranges = resolve_asn_to_ips(asn)
                 for r in asn_ranges:
                     # Check private/reserved
                     if _is_private_or_reserved(r): continue
                     expanded_ranges.append(r)
                 log_event(f"    → {len(asn_ranges)} IP ranges from {asn}")
             except: continue
             
        # Add expanded ranges to main list
        # We do this carefully
        all_ip_ranges.extend(expanded_ranges)
        
        # Add original resolved IPs to ensure they are scanned for ports
        all_ip_ranges.extend(list(phase2_ips))
        
        log_event(f"[*] Phase 4 Complete. Added {len(expanded_ranges)} ranges from ASN expansion and {len(phase2_ips)} direct IPs.")
        tracker.update_asn_expansion(total=len(unique_asns), completed=len(unique_asns), hosts_found=len(all_ip_ranges))
        update_status({
            "phase4_ranges_added": len(expanded_ranges),
            "phase4_direct_ips": len(phase2_ips),
        })

        # ── FIX: PHASE GATE — Pause after Phase 4 (ASN), before Phase 3 (Infra) ──
        # This gate also lets the user choose the Phase 3 scan strategy
        # (Masscan only / Naabu only / sequential / parallel).
        update_status({"phase4_complete": True})
        if not _wait_for_user_gate(scan_context, "gate_phase3",
                                   "Phase 4 (ASN Expansion)",
                                   "Phase 3 (Infrastructure Scan)"):
            return  # User chose to stop
            
    elif mode == "asn_list":
        log_event(f"🚀 Starting Hybrid ASN/IP Scan: {target}")
        update_status({"active_threads": threads, "phase": "🌏 Resolving targets"})
        targets_list = [t.strip() for t in target.split(",")]
        for item in targets_list:
            if _is_stopped(scan_context):
                break
            
            # 1. Check if it's a CIDR or IP
            try:
                if "/" in item:
                    # SECURITY: Skip private/reserved ranges
                    if _is_private_or_reserved(item):
                        log_event(f"[!] Skipping private/reserved range: {item}")
                        continue
                    if ipaddress.ip_network(item, strict=False).version == 4:
                        all_ip_ranges.append(item)
                        continue
                else:
                    # SECURITY: Skip private/reserved IPs
                    if _is_private_or_reserved(item):
                        log_event(f"[!] Skipping private/reserved IP: {item}")
                        continue
                    if ipaddress.ip_address(item).version == 4:
                        all_ip_ranges.append(item)
                        continue
            except ValueError:
                pass # Not an IP/CIDR, try as domain or ASN
            
            # 2. Handle as Domain
            if "." in item and not item.upper().startswith("AS"):
                 ip = await resolve_domain_to_ip(item)
                 if ip:
                     all_ip_ranges.append(ip)
                     continue
            
            # 3. Handle as ASN
            asn = item.upper()
            if asn.startswith("AS"): asn = asn[2:]
            
            if asn.isdigit():
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

    # ── PHASE 3: INFRASTRUCTURE SCANNING ──────────────────────────────
    # FIX: Read user-selected scan strategy from scan_context.
    # Default is 'sequential' (Masscan first, then Naabu) to prevent Mac
    # hangs from uncontrolled parallel execution of both tools.
    phase3_strategy = "sequential"  # safe default
    if scan_context:
        phase3_strategy = scan_context.get("phase3_strategy", "sequential")
    
    log_event(f"📡 Phase 3: Infrastructure Scanning ({ports}) with {threads} threads [Strategy: {phase3_strategy}]")
    
    # Split ranges into chunks
    chunks = []
    chunk_size = max(1, len(all_ip_ranges) // threads)
    for i in range(0, len(all_ip_ranges), chunk_size):
        chunks.append(all_ip_ranges[i:i + chunk_size])
    
    # FIX: Initialize per-tool progress fields for Dashboard real-time display
    update_status({
        "phase": f"📡 Scanning ({phase3_strategy.title()})", 
        "phase3_strategy": phase3_strategy,
        "masscan_total": len(chunks), 
        "masscan_progress": 0,
        "masscan_ranges_total": len(chunks),
        "masscan_ranges_done": 0,
        "masscan_pct": 0,
        "masscan_eta": "Calculating...",
        "masscan_status": "Pending" if phase3_strategy != "naabu_only" else "Skipped",
        "naabu_total": len(chunks), 
        "naabu_progress": 0,
        "naabu_pct": 0,
        "naabu_eta": "Calculating...",
        "naabu_status": "Pending" if phase3_strategy != "masscan_only" else "Skipped",
    })
    
    # FIX: Track start times for ETA calculation
    phase3_start_time = time.time()
    
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
            # SECURITY FIX: Use list-based subprocess to prevent command injection on IP parameter
            cmd = ["nc", "-vz", "-w", "5", ip, "27017"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
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
                    
                    log_event(f"[*] Starting Masscan on chunk {idx + 1}/{len(chunks)} ({len(chunk)} targets) for ports: {clean_ports}")
                    update_status({"masscan_status": "Running"})
                    # SECURITY FIX: Use list-based subprocess to prevent command injection
                    cmd = ["sudo", "masscan", f"-p{clean_ports}", "-iL", chunk_file, 
                           "--rate", str(masscan_rate), "-oJ", output_file, "--wait", "0"]
                    proc = await asyncio.create_subprocess_exec(*cmd)
                    await proc.communicate()
                    
                    if os.path.exists(output_file):
                        async with m_lock:
                            m_files.append(output_file)
                finally:
                    if os.path.exists(chunk_file): os.remove(chunk_file)
        finally:
            # FIX: Update progress with ETA calculation for real-time Dashboard
            async with tracker_lock:
                nonlocal m_done_count
                m_done_count += 1
                elapsed = time.time() - phase3_start_time
                m_pct = int((m_done_count / max(len(chunks), 1)) * 100)
                if m_done_count > 0:
                    eta_seconds = int((elapsed / m_done_count) * (len(chunks) - m_done_count))
                    m_eta = f"{eta_seconds // 60}m {eta_seconds % 60}s" if eta_seconds > 0 else "Done"
                else:
                    m_eta = "Calculating..."
                update_status({
                    "masscan_progress": m_done_count,
                    "masscan_ranges_done": m_done_count,
                    "masscan_pct": m_pct,
                    "masscan_eta": m_eta,
                    "masscan_status": "Completed" if m_done_count >= len(chunks) else "Running",
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
                    
                    log_event(f"[*] Starting Naabu on chunk {idx + 1}/{len(chunks)} ({len(chunk)} targets) for ports: {clean_ports}")
                    update_status({"naabu_status": "Running"})
                    # SECURITY FIX: Use list-based subprocess to prevent command injection
                    cmd = ["naabu", "-list", chunk_file, "-p", clean_ports, "-silent", "-o", output_file]
                    proc = await asyncio.create_subprocess_exec(*cmd)
                    await proc.communicate()
                    
                    if os.path.exists(output_file):
                        async with n_lock:
                            n_files.append(output_file)
                finally:
                    if os.path.exists(chunk_file): os.remove(chunk_file)
        finally:
            # FIX: Update progress with ETA calculation for real-time Dashboard
            async with tracker_lock:
                nonlocal n_done_count
                n_done_count += 1
                # ETA uses naabu-specific start time for sequential mode
                n_elapsed = time.time() - phase3_start_time
                n_pct = int((n_done_count / max(len(chunks), 1)) * 100)
                if n_done_count > 0:
                    n_eta_seconds = int((n_elapsed / n_done_count) * (len(chunks) - n_done_count))
                    n_eta = f"{n_eta_seconds // 60}m {n_eta_seconds % 60}s" if n_eta_seconds > 0 else "Done"
                else:
                    n_eta = "Calculating..."
                update_status({
                    "naabu_progress": n_done_count,
                    "naabu_pct": n_pct,
                    "naabu_eta": n_eta,
                    "naabu_status": "Completed" if n_done_count >= len(chunks) else "Running",
                })
        return True

    async def scan_chunk(idx, chunk):
        """FIX: Replaced — now only used in 'parallel' strategy as a fallback."""
        if _is_stopped(scan_context):
            return
        tasks = [
            run_masscan_chunk(idx, chunk),
            run_naabu_chunk(idx, chunk)
        ]
        if has_mongo:
            tasks.append(run_nc_chunk(idx, chunk))
        await asyncio.gather(*tasks)

    # ── FIX: Phase 3 Execution Strategy ──────────────────────────────────
    # Previous bug: Masscan + Naabu always ran in parallel on ALL chunks
    # simultaneously, causing Mac to hang from resource exhaustion.
    # Now the user selects the strategy on the Dashboard before Phase 3.
    try:
        if phase3_strategy == "masscan_only":
            # Only Masscan
            log_event("[*] Strategy: Masscan only")
            update_status({"naabu_status": "Skipped"})
            for i, c in enumerate(chunks):
                if _is_stopped(scan_context): break
                await run_masscan_chunk(i, c)
            if has_mongo:
                for i, c in enumerate(chunks):
                    if _is_stopped(scan_context): break
                    await run_nc_chunk(i, c)
                    
        elif phase3_strategy == "naabu_only":
            # Only Naabu
            log_event("[*] Strategy: Naabu only")
            update_status({"masscan_status": "Skipped"})
            for i, c in enumerate(chunks):
                if _is_stopped(scan_context): break
                await run_naabu_chunk(i, c)
            if has_mongo:
                for i, c in enumerate(chunks):
                    if _is_stopped(scan_context): break
                    await run_nc_chunk(i, c)

        elif phase3_strategy == "sequential":
            # DEFAULT: Run all Masscan chunks first, THEN all Naabu chunks
            # This prevents resource exhaustion on macOS
            log_event("[*] Strategy: Sequential (Masscan → Naabu)")
            update_status({"naabu_status": "Waiting (Masscan running)"})
            for i, c in enumerate(chunks):
                if _is_stopped(scan_context): break
                await run_masscan_chunk(i, c)
            
            if not _is_stopped(scan_context):
                # Reset ETA timer for Naabu phase
                phase3_start_time = time.time()
                update_status({"masscan_status": "Completed", "naabu_status": "Running"})
                for i, c in enumerate(chunks):
                    if _is_stopped(scan_context): break
                    await run_naabu_chunk(i, c)
            
            if has_mongo:
                for i, c in enumerate(chunks):
                    if _is_stopped(scan_context): break
                    await run_nc_chunk(i, c)

        elif phase3_strategy == "parallel":
            # Advanced: Original parallel behavior (both tools on all chunks)
            log_event("[*] Strategy: Parallel (Advanced — both tools simultaneously)")
            update_status({"masscan_status": "Running", "naabu_status": "Running"})
            await asyncio.gather(*(scan_chunk(i, c) for i, c in enumerate(chunks)))

        else:
            # Unknown strategy — fall back to sequential
            log_event(f"[!] Unknown strategy '{phase3_strategy}', falling back to sequential.")
            for i, c in enumerate(chunks):
                if _is_stopped(scan_context): break
                await run_masscan_chunk(i, c)
            for i, c in enumerate(chunks):
                if _is_stopped(scan_context): break
                await run_naabu_chunk(i, c)

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
