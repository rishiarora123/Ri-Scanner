import asyncio
import re
import json
import aiohttp
import os
import sys
import subprocess
import time
import math
import shutil
import concurrent.futures
import ssl
import threading
from .config import ScannerConfig
from .ssl_helper import fetch_certificate
from .http_helper import check_site
from .utils import log_to_server, resolve_asn_to_ips

def log_event(message, to_terminal=False):
    if to_terminal:
        print(message)
    log_to_server(message)


async def run_enhanced_recon_tools(domain):
    """
    Run all available recon tools on domain and return aggregated results.
    This uses the tools framework to run multiple tools and deduplicate results.
    """
    try:
        from .recon_runner import get_recon_runner
        
        runner = get_recon_runner()
        log_event(f"[*] Running enhanced recon tools on {domain}...")
        
        # Run subdomain enumeration with all available tools
        results = await runner.run_subdomain_recon(domain)
        
        subdomains = results.get("subdomains", [])
        tool_results = results.get("tool_results", {})
        errors = results.get("errors", [])
        
        # Log results per tool
        for tool_id, subs in tool_results.items():
            if isinstance(subs, list):
                log_event(f"[+] {tool_id}: Found {len(subs)} subdomains")
        
        # Log any errors
        for err in errors:
            log_event(f"[!] {err.get('tool', 'unknown')}: {err.get('error', 'Unknown error')}")
        
        log_event(f"[*] Total unique subdomains found: {len(subdomains)}")
        
        # Save aggregated results
        output_dir = os.path.join("Tmp", f"{domain}_data")
        os.makedirs(output_dir, exist_ok=True)
        
        subdomains_file = os.path.join(output_dir, "all_subdomains.txt")
        with open(subdomains_file, 'w') as f:
            f.write('\n'.join(sorted(subdomains)))
        log_event(f"[*] Saved {len(subdomains)} subdomains to {subdomains_file}")
        
        # Save per-tool results for reference
        tools_results_file = os.path.join(output_dir, "recon_tools_results.json")
        import json as json_module
        with open(tools_results_file, 'w') as f:
            json_module.dump({
                "domain": domain,
                "total_subdomains": len(subdomains),
                "tool_counts": {k: len(v) if isinstance(v, list) else 0 for k, v in tool_results.items()},
                "errors": errors
            }, f, indent=2)
        
        # Save to subdomain_manager (files + MongoDB)
        try:
            from .subdomain_manager import get_subdomain_manager
            manager = get_subdomain_manager()
            manager.save_subdomains(domain, subdomains, source="recon")
            log_event(f"[*] Saved subdomains to database")
        except Exception as e:
            log_event(f"[!] Database save warning: {e}")
        
        return subdomains
        
    except ImportError as e:
        log_event(f"[!] Enhanced recon not available: {e}")
        return []
    except Exception as e:
        log_event(f"[!] Enhanced recon error: {e}")
        return []


def _run_async_recon_in_thread(domain):
    """Run async recon in a separate thread with its own event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(run_enhanced_recon_tools(domain))
        return result
    finally:
        loop.close()


def run_recon(domain, threads, bgp_url=None):
    log_event(f"[*] Starting Recon for {domain}...")
    
    # First, run enhanced recon tools to gather subdomains
    # Use a thread executor to avoid event loop conflicts
    subdomains = []
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_async_recon_in_thread, domain)
            subdomains = future.result(timeout=300)  # 5 min timeout
            log_event(f"[*] Enhanced recon gathered {len(subdomains)} unique subdomains")
    except Exception as e:
        log_event(f"[!] Enhanced recon failed, continuing with legacy: {e}")
    
    try:
        # Assuming CWD is the project root, and we moved final_recon.sh to app/core/
        script_path = os.path.join("app", "core", "final_recon.sh")
        cmd = ["bash", script_path, "-d", domain, "-t", str(threads)]
        if bgp_url:
            cmd.extend(["-u", bgp_url])

        subprocess.run(cmd, check=True)
        
        ip_file = os.path.join(os.getcwd(), "Tmp", f"{domain}_data", f"All_{domain}_IP_Range.txt")
        
        if os.path.exists(ip_file):
            log_event(f"[*] Recon successful. IP list found at: {ip_file}")
            return ip_file
        else:
            log_event(f"[!] Recon finished but IP file not found at: {ip_file}")
            return None
    except subprocess.CalledProcessError as e:
        log_event(f"[!] Recon script failed: {e}")
        return None


def split_and_run_masscan(ip_file, final_output_file, config, num_chunks, stop_event=None):
    log_event(f"[*] Splitting IP list and running Masscan in parallel...")

    # Create Tmp/Masscan directory for chunks to keep things clean
    masscan_tmp_dir = os.path.join("Tmp", "Masscan")
    if os.path.exists(masscan_tmp_dir):
        shutil.rmtree(masscan_tmp_dir)
    os.makedirs(masscan_tmp_dir)
    
    with open(ip_file, 'r') as f:
        all_lines = [line.strip() for line in f if line.strip()]
    
    total_ranges = len(all_lines)
    if not all_lines:
        log_event("[!] IP file is empty.")
        return []

    if num_chunks <= 0:
        # Auto detect optimal chunks
        import multiprocessing
        try:
            cpu_count = multiprocessing.cpu_count()
        except (NotImplementedError, OSError):
            cpu_count = 4
        # Heuristic: Use CPU count as baseline, but ensure at least 1 chunk and cap at 50 to avoid overhead
        num_chunks = max(1, min(total_ranges, cpu_count * 2, 50))
    elif total_ranges < num_chunks:
        num_chunks = max(1, total_ranges)
        
    chunk_size = math.ceil(total_ranges / num_chunks)
    temp_files = []
    temp_results = []
    chunk_counts = []

    for i in range(num_chunks):
        chunk_lines = all_lines[i * chunk_size : (i + 1) * chunk_size]
        if not chunk_lines:
            continue
            
        chunk_input = os.path.join(masscan_tmp_dir, f"temp_chunk_{i}.txt")
        chunk_output = os.path.join(masscan_tmp_dir, f"temp_res_{i}.txt")
        
        with open(chunk_input, 'w') as f:
            f.write('\n'.join(chunk_lines))
            
        temp_files.append(chunk_input)
        temp_results.append(chunk_output)
        chunk_counts.append(len(chunk_lines))

    # Store chunk details for status reporting
    chunk_details = []
    for i in range(len(temp_files)):
        # Get first and last IP range for display
        chunk_start_idx = i * len(all_lines) // num_chunks
        chunk_end_idx = (i + 1) * len(all_lines) // num_chunks
        chunk_ranges = all_lines[chunk_start_idx:chunk_end_idx]
        
        first_range = chunk_ranges[0] if chunk_ranges else "N/A"
        last_range = chunk_ranges[-1] if chunk_ranges else "N/A"
        
        chunk_details.append({
            "id": i,
            "status": "pending",
            "first_range": first_range,
            "last_range": last_range,
            "total": len(chunk_ranges),
            "processed": 0
        })

    def run_single_masscan(input_path, output_path, idx):
        # Get chunk detail
        chunk_info = chunk_details[idx] if idx < len(chunk_details) else {}
        
        # Notify Running with full details
        try:
            import urllib.request
            update_data = {
                "id": idx, 
                "status": "running",
                "first_range": chunk_info.get("first_range", ""),
                "last_range": chunk_info.get("last_range", ""),
                "total": chunk_info.get("total", 0),
                "processed": 0
            }
            data = json.dumps({"chunk_update": update_data}).encode('utf-8')
            req = urllib.request.Request("http://127.0.0.1:5000/update_status", data=data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

        cmd = f"sudo masscan -p80,443,8080,8443,4443 --rate {config.masscan_rate} --wait 0 -iL '{input_path}' -oL '{output_path}'"
        try:
             # Basic execution without real-time parsing to ensure stability as requested
             subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=None) 
        except Exception as e:
            if "gaierror" not in str(e).lower():
                log_to_server(f"[!] Masscan Chunk {idx} error: {e}")
        
        # Cleanup input file immediately to save space/inodes
        try:
            if os.path.exists(input_path):
                os.remove(input_path)
        except OSError:
            pass
        
        # Notify Completed with full details
        try:
            import urllib.request
            update_data = {
                "id": idx, 
                "status": "completed",
                "processed": chunk_info.get("total", 0)
            }
            data = json.dumps({"chunk_update": update_data}).encode('utf-8')
            req = urllib.request.Request("http://127.0.0.1:5000/update_status", data=data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

    log_event(f"[*] Running {len(temp_files)} Masscan instances concurrently (Unlimited)...")
    total_chunks = len(temp_files)
    completed_chunks = 0
    completed_ranges = 0
    start_time = time.time()
    
    # Send initial status
    try:
        import urllib.request
        data = json.dumps({
            "phase": "Masscan",
            "masscan_total": total_chunks,
            "masscan_progress": 0,
            "masscan_ranges_total": total_ranges,
            "masscan_ranges_done": 0,
            "masscan_chunks_status": [{"id": i, "status": "pending"} for i in range(total_chunks)]
        }).encode('utf-8')
        req = urllib.request.Request("http://127.0.0.1:5000/update_status", data=data, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req)
    except Exception: 
        pass
    
    # Restore High Concurrency - No Limits as requested
    max_masscan_workers = len(temp_files)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_masscan_workers) as executor:
        future_to_index = {executor.submit(run_single_masscan, temp_files[i], temp_results[i], i): i for i in range(len(temp_files))}
        
        try:
            for future in concurrent.futures.as_completed(future_to_index):
                if stop_event and stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                idx = future_to_index[future]
                completed_chunks += 1
                completed_ranges += chunk_counts[idx]
                
                # Calculate ETR
                elapsed = time.time() - start_time
                etr_str = "Calculating..."
                if completed_chunks > 0:
                    avg_chunk_time = elapsed / completed_chunks
                    remaining_chunks = total_chunks - completed_chunks
                    etr_seconds = remaining_chunks * avg_chunk_time
                    if etr_seconds > 60:
                        etr_str = f"{int(etr_seconds // 60)}m {int(etr_seconds % 60)}s"
                    else:
                        etr_str = f"{int(etr_seconds)}s"

                # Update server status for dashboard
                try:
                    import urllib.request
                    data = json.dumps({
                        "masscan_progress": completed_chunks,
                        "masscan_total": total_chunks,
                        "masscan_ranges_done": completed_ranges,
                        "masscan_ranges_total": total_ranges,
                        "estimated_remaining": etr_str
                    }).encode('utf-8')
                    req = urllib.request.Request("http://127.0.0.1:5000/update_status", data=data, headers={'Content-Type': 'application/json'})
                    urllib.request.urlopen(req, timeout=2)
                except Exception:
                    pass
                
                log_event(f"Masscan Chunk {idx+1}/{total_chunks} finished")
        except Exception as e:
            log_event(f"[!] Masscan Thread Error: {e}")

    if stop_event and stop_event.is_set():
        return temp_files + temp_results

    log_event("[*] Merging Masscan results...")
    with open(final_output_file, 'w') as outfile:
        for res_file in temp_results:
            if os.path.exists(res_file):
                with open(res_file, 'r') as infile:
                    outfile.write(infile.read())
                temp_files.append(res_file)

    return temp_files

async def process_ip(session, ip, port, config):
    async with config.semaphore:
        return await check_site(session, ip, port, config)

async def extract_domains(config, stop_event=None):
    log_event("[*] Starting Domain Extraction and HTTP Probing...")
    if not os.path.exists(config.mass_scan_results_file):
            log_event(f"[!] Masscan results file not found: {config.mass_scan_results_file}")
            return

    # Parse Masscan List results correctly (-oL format is merge-safe)
    targets = []
    try:
        with open(config.mass_scan_results_file, "r") as f:
            for line in f:
                if line.startswith("open"):
                    parts = line.split()
                    if len(parts) >= 4:
                        # Format: open <proto> <port> <ip> <timestamp>
                        port = parts[2]
                        ip = parts[3]
                        if ip and port:
                            targets.append((ip, int(port)))
    except Exception as e:
        log_event(f"[!] Error parsing masscan results: {e}")
        return

    total_targets = len(targets)
    log_event(f"[*] Found {total_targets} target services (IP:Port). Processing...")

    start_time = time.time()
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=config.MAX_CONCURRENT, ssl=False)
    ) as session:
        
        # Reset extraction status (async)
        try:
            async with session.post("http://127.0.0.1:5000/update_status", 
                json={"phase": "Extraction", "extraction_total": total_targets, "extraction_progress": 0, "found_count": 0, "estimated_remaining": "Calculating..."}, 
                timeout=2) as r:
                pass
        except Exception:
            pass

        active_tasks = 0
        
        async def tracked_process_ip(session, ip, port, config):
            nonlocal active_tasks
            active_tasks += 1
            try:
                return await process_ip(session, ip, port, config)
            finally:
                active_tasks -= 1

        tasks = []
        for ip, port in targets:
            tasks.append(tracked_process_ip(session, ip, port, config))
        
        completed_count = 0
        found_count = 0
        batch_results = []
        
        for future in asyncio.as_completed(tasks):
            if stop_event and stop_event.is_set():
                break
            result = await future
            completed_count += 1
            
            if result:
                found_count += 1
                # result is { 'http_responseForIP': { ... } }
                inner_key = next(iter(result.keys()))
                inner_res = result[inner_key]
                log_event(f"FOUND: {inner_res.get('title', 'No Title')} - {inner_res.get('request')}")
                batch_results.append(result)
            
            if completed_count % 10 == 0 or completed_count == total_targets:
                # Calculate ETR
                elapsed = time.time() - start_time
                etr_str = "Calculating..."
                if completed_count > 0:
                    rate = completed_count / elapsed
                    if rate > 0:
                        remaining_targets = total_targets - completed_count
                        etr_seconds = remaining_targets / rate
                        if etr_seconds > 60:
                            etr_str = f"{int(etr_seconds // 60)}m {int(etr_seconds % 60)}s"
                        else:
                            etr_str = f"{int(etr_seconds)}s"

                try:
                    # Send active_threads (Non-blocking)
                    asyncio.create_task(session.post("http://127.0.0.1:5000/update_status", 
                        json={
                            "extraction_progress": completed_count, 
                            "extraction_total": total_targets,
                            "found_count": found_count, 
                            "active_threads": active_tasks,
                            "estimated_remaining": etr_str
                        }, timeout=2))
                except Exception:
                    pass

            if len(batch_results) >= 50:
                try:
                    async with session.post(config.server_url, data=json.dumps(batch_results), headers={"Content-Type": "application/json"}, ssl=False) as res:
                        pass
                except Exception:
                    pass
                batch_results = []

        if batch_results:
            try:
                async with session.post(config.server_url, data=json.dumps(batch_results), headers={"Content-Type": "application/json"}, ssl=False) as res:
                    pass
            except aiohttp.ClientError:
                pass

    log_event("[*] Extraction completed.")

async def run_scan_logic(mode, target_input, threads=50, bgp_url=None, masscan_rate=10000, masscan_chunks=10, scan_context=None):
    # mode: 'recon', 'masscan_file', 'ip_file'
    
    # Unwrap context
    stop_event = scan_context.get("stop_event") if scan_context else None
    
    config = ScannerConfig()
    config.masscan_rate = masscan_rate
    temp_files_to_clean = []
    json_export_path = None
    
    try:
        if mode == 'recon':
            ip_file = run_recon(target_input, threads, bgp_url)
            if not ip_file: return
            config.ips_file = ip_file
            domain_dir = os.path.dirname(ip_file)
            config.mass_scan_results_file = os.path.join(domain_dir, "masscanResults.txt")
            json_export_path = os.path.join(domain_dir, f"{target_input}_json_data.json")
            
            chunk_temps = split_and_run_masscan(config.ips_file, config.mass_scan_results_file, config, masscan_chunks, stop_event)
            temp_files_to_clean.extend(chunk_temps)
            
        elif mode == 'masscan_file':
            config.mass_scan_results_file = target_input
            json_export_path = f"{target_input}_json_data.json"
            # No masscan needed, just extract
            
        elif mode == 'ip_file':
            config.ips_file = target_input
            # Create a temp masscan output file in Tmp
            if not os.path.exists("Tmp"): os.makedirs("Tmp")
            config.mass_scan_results_file = os.path.join("Tmp", f"masscan_from_ip_file_{int(time.time())}.txt")
            json_export_path = os.path.join("Tmp", f"scan_json_data_{int(time.time())}.json")
            
            chunk_temps = split_and_run_masscan(config.ips_file, config.mass_scan_results_file, config, masscan_chunks, stop_event)
            temp_files_to_clean.extend(chunk_temps)

        elif mode == 'asn_list':
            # Resolve ASNs to IPs
            log_event("[*] Expanding ASNs to IP ranges...")
            asns = re.split(r'[,\s]+', target_input)
            all_ips = []
            for asn in asns:
                if asn.strip():
                    ips = resolve_asn_to_ips(asn.strip())
                    all_ips.extend(ips)
                    log_event(f"[*] {asn.strip()}: Found {len(ips)} prefixes")
            
            if not all_ips:
                log_event("[!] No IP ranges found for the provided ASNs.")
                return

            # Create a temporary IP list file
            if not os.path.exists("Tmp"): os.makedirs("Tmp")
            asn_ip_file = os.path.join("Tmp", f"asn_ips_{int(time.time())}.txt")
            with open(asn_ip_file, 'w') as f:
                f.write('\n'.join(all_ips))
            
            config.ips_file = asn_ip_file
            temp_files_to_clean.append(asn_ip_file)
            
            config.mass_scan_results_file = os.path.join("Tmp", f"masscan_from_asn_{int(time.time())}.txt")
            json_export_path = os.path.join("Tmp", f"asn_scan_json_{int(time.time())}.json")
            
            chunk_temps = split_and_run_masscan(config.ips_file, config.mass_scan_results_file, config, masscan_chunks, stop_event)
            temp_files_to_clean.extend(chunk_temps)

        if not (stop_event and stop_event.is_set()):
            await extract_domains(config, stop_event)
            
            if json_export_path:
                log_event(f"[*] Exporting results to {json_export_path}...")
                try:
                    import urllib.request
                    data = json.dumps({"filename": os.path.abspath(json_export_path)}).encode('utf-8')
                    req = urllib.request.Request("http://127.0.0.1:5000/export", data=data, headers={'Content-Type': 'application/json'})
                    urllib.request.urlopen(req)
                    log_event(f"[*] Export complete.")
                except Exception as e:
                    log_event(f"[!] Export failed: {e}")

        log_event("[*] Workflow Finished.")

    except Exception as e:
        log_event(f"[!] Workflow Error: {e}")
    finally:
        # Cleanup logic similar to main.py
        for f in temp_files_to_clean:
            if os.path.exists(f): os.remove(f)
            
        if stop_event and stop_event.is_set():
            log_event("[!] Scan stopped by user.")
            
            keep_files = False
            if scan_context and scan_context.get("keep_files"):
                keep_files = True
                
            if keep_files:
                log_event("[*] Keeping data files as requested.")
            else:
                log_event("[!] Deleting collected data immediately...")
                # Aggressive cleanup
                if mode == 'recon' and 'domain_dir' in locals() and os.path.exists(domain_dir):
                    shutil.rmtree(domain_dir, ignore_errors=True)
                
                if mode == 'ip_file' and os.path.exists(config.mass_scan_results_file):
                    try: os.remove(config.mass_scan_results_file)
                    except OSError: pass
                
                if target_input and "Tmp" in target_input and os.path.exists(target_input):
                    try: os.remove(target_input)
                    except OSError: pass