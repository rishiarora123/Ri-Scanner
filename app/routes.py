from flask import Blueprint, render_template, request, jsonify, Response, current_app
import threading
import os
import json
import asyncio
from werkzeug.utils import secure_filename
from .core import core
from bson import json_util
import re
from bson.regex import Regex

main_bp = Blueprint('main', __name__)

import subprocess

# Global Context
scan_status = {
    "phase": "Idle",
    "masscan_progress": 0,
    "masscan_total": 0,
    "masscan_ranges_done": 0,
    "masscan_ranges_total": 0,
    "masscan_chunks_status": [],
    "extraction_progress": 0,
    "extraction_total": 0,
    "found_count": 0,
    "active_threads": 0,
    "estimated_remaining": "N/A"
}
scan_logs = []
# Context acts as a mutable shared object
scan_context = {
    "stop_event": threading.Event(),
    "keep_files": False
}

def run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(coro)
    loop.close()

@main_bp.route("/")
def home():
    return render_template("index.html")

@main_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@main_bp.route("/start_scan", methods=["POST"])
def start_scan():
    mode = request.form.get("mode")
    target = None
    bgp_url = request.form.get("bgp_url")
    masscan_rate = int(request.form.get("masscan_rate", 10000))
    masscan_chunks = int(request.form.get("masscan_chunks", 0))
    
    if not os.path.exists("Tmp"):
        os.makedirs("Tmp")

    if mode == "recon":
        target = request.form.get("domain")
    elif mode in ["masscan_file", "ip_file"]:
        if 'file' not in request.files:
            return "No file uploaded", 400
        file = request.files['file']
        if file.filename == '':
            return "No selected file", 400
        
        filename = secure_filename(file.filename)
        save_path = os.path.join("Tmp", filename)
        file.save(save_path)
        target = save_path

    # Reset Status
    global scan_status, scan_logs, scan_context
    scan_status.update({
        "phase": "Initializing...", 
        "masscan_progress": 0, "masscan_total": 0, 
        "masscan_ranges_done": 0, "masscan_ranges_total": 0, 
        "masscan_chunks_status": [], 
        "extraction_progress": 0, "extraction_total": 0, 
        "found_count": 0, "active_threads": 0,
        "estimated_remaining": "Calculating..."
    })
    scan_logs = []

    # Reset Context
    scan_context["stop_event"].clear()
    scan_context["keep_files"] = False
    
    # Run the core logic in a separate thread
    t = threading.Thread(target=run_async_in_thread, args=(core.run_scan_logic(mode, target, 50, bgp_url, masscan_rate, masscan_chunks, scan_context),))
    t.start()

    return jsonify({"status": "started"})

@main_bp.route("/stop_scan", methods=["POST"])
def stop_scan():
    data = request.get_json() or {}
    keep_files = data.get("save", False)
    
    scan_context["keep_files"] = keep_files
    scan_context["stop_event"].set()
    
    # Force kill masscan immediately
    try:
        subprocess.run(["sudo", "killall", "masscan"], capture_output=True)
    except: 
        pass
        
    scan_status["phase"] = "Stopping..."
    return jsonify({"status": "stopped"})

@main_bp.route("/get_status", methods=["GET"])
def get_status_route():
    return jsonify(scan_status)

@main_bp.route("/update_status", methods=["POST"])
def update_status_route():
    global scan_status
    data = request.get_json()
    if data:
        if "chunk_update" in data:
            update = data.pop("chunk_update")
            idx = update.get("id")
            status = update.get("status")
            if idx is not None and "masscan_chunks_status" in scan_status and 0 <= idx < len(scan_status["masscan_chunks_status"]):
                scan_status["masscan_chunks_status"][idx]["status"] = status
        
        # Merge dicts
        for k, v in data.items():
            if k == "masscan_chunks_status" and not v and scan_status.get("masscan_chunks_status"):
                 continue # Don't overwrite existing chunks with empty list
            scan_status[k] = v
            
    return jsonify({"status": "ok"})

@main_bp.route("/log_update", methods=["POST"]) # Renamed from /log to be distinct
def log_message():
    data = request.get_json()
    msg = data.get("log") or data.get("message")
    if msg:
        scan_logs.append(msg)
        if len(scan_logs) > 1000: 
            scan_logs.pop(0)
    return jsonify({"status": "ok"})

@main_bp.route("/get_logs", methods=["GET"])
def get_logs():
    return jsonify(scan_logs)

@main_bp.route("/export", methods=["POST"])
def export_data():
    try:
        data = request.get_json()
        filename = data.get("filename")
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
            
        cursor = current_app.db["sslchecker"].find({}, {"_id": 0})
        results = list(cursor)
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4, default=json_util.default)
            
        return jsonify({"status": "exported", "count": len(results), "path": filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route("/insert", methods=["POST"])
def insert():
    try:
        results_json = request.get_json()
        if results_json:
            current_app.db["sslchecker"].insert_many(results_json)
        return jsonify({"message": "Inserted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Search Endpoints ---

@main_bp.route("/search/title", methods=["GET"])
def search_title():
    try:
        query = request.args.get("q", "").strip()
        
        if not query:
            # Return recent results if no query
            # Sort by _id descending to get newest first
            results = list(current_app.db["sslchecker"].find({}, {"_id": 0}).sort("_id", -1).limit(50))
            return jsonify(results)
        
        regex = Regex(rf".*{re.escape(query)}.*", "i")
        db_query = {
            "$or": [
                {"http_responseForIP.title": regex},
                {"https_responseForIP.title": regex},
                {"http_responseForDomainName.title": regex},
                {"https_responseForDomainName.title": regex},
                {"http_responseForIP.domain": regex}, # Also search domain field
                {"https_responseForIP.domain": regex},
                {"http_responseForIP.ip": regex}, # Also search IP
            ]
        }
        results = list(current_app.db["sslchecker"].find(db_query, {"_id": 0}).limit(100))
        return jsonify(results)
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

# Add other search endpoints as needed (IP, Domain, etc.) similar to above
