#!/bin/bash

# Force Verbose by default for debugging
VERBOSE=true
THREADS=50
API_URL="http://127.0.0.1:5000"

send_status() {
    curl -s -X POST -H "Content-Type: application/json" -d "{\"phase\": \"$1\"}" "$API_URL/update_status" > /dev/null 2>&1
}

send_log() {
    # Escape backslashes and double quotes for JSON
    local msg
    msg=$(echo "$1" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
    curl -s -X POST -H "Content-Type: application/json" -d "{\"log\": \"$msg\"}" "$API_URL/log_update" > /dev/null 2>&1
}

usage() {
    echo "Usage: $0 -d <domain> -t <threads> [-u <BGP_URL>]"
    exit 1
}

while getopts "d:t:u:v" opt; do
  case $opt in
    d) DOMAIN="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    u) URL="$OPTARG" ;;
    v) VERBOSE=true ;;
    *) usage ;;
  esac
done

if [ -z "$DOMAIN" ]; then echo "❌ Error: Domain (-d) is required"; usage; fi

# Setup Folder
mkdir -p "Tmp"
DATA_DIR="Tmp/${DOMAIN}_data"
mkdir -p "$DATA_DIR"
ABS_DIR=$(cd "$DATA_DIR" && pwd)

echo "--------------------------------------------------"
echo "🛠️  DEBUG MODE: RECON FOR $DOMAIN"
echo "📂 Working Directory: $ABS_DIR"
echo "--------------------------------------------------"

# --- CHECK DEPENDENCIES ---
for tool in subfinder dig curl whois nc; do
    if ! command -v $tool &> /dev/null; then
        echo "❌ CRITICAL: '$tool' is not installed. Please install it first."
        exit 1
    fi
done

# --- STEP 1: SUBDOMAIN DISCOVERY ---
echo "[Step 1] Finding subdomains..."
send_status "Step 1: Finding subdomains (Subfinder)"
send_log "[Step 1] Finding subdomains for $DOMAIN..."
# Run subfinder with verbose output to screen to see errors
subfinder -d "$DOMAIN" -silent > "$ABS_DIR/subdomains.txt"

SUB_COUNT=$(wc -l < "$ABS_DIR/subdomains.txt")
echo "   ↳ Status: Found $SUB_COUNT subdomains."
send_log "   ↳ Status: Found $SUB_COUNT subdomains."

if [ "$SUB_COUNT" -eq 0 ]; then
    echo "   ⚠️  WARNING: Subfinder found nothing. Adding root domain '$DOMAIN' to continue."
    echo "$DOMAIN" > "$ABS_DIR/subdomains.txt"
fi

# --- STEP 2: DOMAIN -> IP -> ASN ---
echo "[Step 2] Resolving IPs (Threads: $THREADS)..."
send_status "Step 2: Resolving IPs (Dig)"
send_log "[Step 2] Resolving IPs..."

# Sanitize input
grep -v '^$' "$ABS_DIR/subdomains.txt" | sed 's/^\.//' | sort -u > "$ABS_DIR/clean_subs.txt"

# Resolve IPs
# Using -P for parallelism. Added verification check.
cat "$ABS_DIR/clean_subs.txt" | xargs -P "$THREADS" -I {} dig +short {} | \
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u > "$ABS_DIR/step2_ips.txt"

IP_COUNT=$(wc -l < "$ABS_DIR/step2_ips.txt")
echo "   ↳ Status: Resolved $IP_COUNT unique IP addresses."
send_log "   ↳ Status: Resolved $IP_COUNT unique IP addresses."

if [ "$IP_COUNT" -eq 0 ]; then
    echo "   ⚠️  WARNING: No IPs resolved. Skipping ASN mapping for Step 2."
    > "$ABS_DIR/step2_ASN.txt"
else
    # Map to ASNs
    echo "   ↳ Mapping IPs to ASNs via Team Cymru..."
    send_status "Step 2: Mapping IPs to ASNs"
    { echo "begin"; cat "$ABS_DIR/step2_ips.txt"; echo "end"; } | \
    nc whois.cymru.com 43 | grep '|' | awk -F'|' '{print "AS"$1}' | sed 's/ //g' | sort -u > "$ABS_DIR/step2_ASN.txt"
    echo "   ↳ Status: Found $(wc -l < "$ABS_DIR/step2_ASN.txt") ASNs from subdomains."
    send_log "   ↳ Status: Found $(wc -l < "$ABS_DIR/step2_ASN.txt") ASNs from subdomains."
fi

# --- STEP 3: BGP.HE.NET INTEGRATION ---
if [ -n "$URL" ]; then
    echo "[Step 3] Fetching BGP data..."
    send_status "Step 3: Fetching BGP Data"
    send_log "[Step 3] Fetching BGP data from URL..."
    
    # Using more robust curl options:
    # -k: Allow insecure (SSL)
    # -L: Follow redirects
    # --fail: Fail silently on server errors so we can catch it
    curl -k -L --fail -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "$URL" -o "$ABS_DIR/page.html"
    
    if [ ! -f "$ABS_DIR/page.html" ] || [ ! -s "$ABS_DIR/page.html" ]; then
        echo "   ❌ ERROR: Download failed. page.html is missing or empty."
        echo "      Trying backup method: dumping URL to text..."
        # Backup: Try downloading just the text if HTML fails
        curl -s "$URL" > "$ABS_DIR/page.html"
    fi

    # Check again
    if [ -s "$ABS_DIR/page.html" ]; then
        grep -oE 'AS[0-9]+' "$ABS_DIR/page.html" | sort -u > "$ABS_DIR/bgp_ASN.txt"
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' "$ABS_DIR/page.html" | sort -u > "$ABS_DIR/BGP_IPV4.txt"
        echo "   ↳ Status: Extracted $(wc -l < "$ABS_DIR/bgp_ASN.txt") ASNs from URL."
        send_log "   ↳ Status: Extracted $(wc -l < "$ABS_DIR/bgp_ASN.txt") ASNs from URL."
        rm "$ABS_DIR/page.html"
    else
        echo "   ❌ CRITICAL: Could not retrieve data from URL. Skipping Step 3."
        > "$ABS_DIR/bgp_ASN.txt"
        > "$ABS_DIR/BGP_IPV4.txt"
    fi
else
    echo "[Step 3] No URL provided. Skipping."
    > "$ABS_DIR/bgp_ASN.txt"
    > "$ABS_DIR/BGP_IPV4.txt"
fi

# --- STEP 4: COMBINE AND EXPAND ---
echo "[Step 4] Combining ASNs and Expanding Ranges..."
send_status "Step 4: Combining ASNs"
send_log "[Step 4] Combining ASNs and Expanding Ranges..."

# Merge ASNs
cat "$ABS_DIR/step2_ASN.txt" "$ABS_DIR/bgp_ASN.txt" 2>/dev/null | sort -u > "$ABS_DIR/combined_ASNs.txt"
TOTAL_ASNS=$(wc -l < "$ABS_DIR/combined_ASNs.txt")

if [ "$TOTAL_ASNS" -eq 0 ]; then
    echo "❌ CRITICAL: No ASNs found from Domain OR URL. Exiting."
    exit 1
fi

echo "   ↳ Expanding $TOTAL_ASNS ASNs (this may take time)..."
> "$ABS_DIR/expanded_ranges.txt"
send_status "Step 4: Expanding ASN Ranges"

count=0
while read -r asn; do
    [ -z "$asn" ] && continue
    ((count++))
    clean_asn=$(echo "$asn" | grep -oE '[0-9]+')
    echo -ne "      Processing [$count/$TOTAL_ASNS] AS$clean_asn... \r"
    
    # RADB Query with error checking
    whois -h whois.radb.net -- "-i origin AS$clean_asn" | \
    grep -E '^route:' | awk '{print $2}' >> "$ABS_DIR/expanded_ranges.txt"
    
    # Small sleep to prevent timeouts
    sleep 0.2
done < "$ABS_DIR/combined_ASNs.txt"
echo "" # New line

# --- FINAL CONSOLIDATION ---
cat "$ABS_DIR/expanded_ranges.txt" "$ABS_DIR/BGP_IPV4.txt" "$ABS_DIR/step2_ips.txt" 2>/dev/null | \
grep -E '^[0-9]' | sort -u > "$ABS_DIR/All_${DOMAIN}_IP_Range.txt"

FINAL_COUNT=$(wc -l < "$ABS_DIR/All_${DOMAIN}_IP_Range.txt")

echo "--------------------------------------------------"
echo "✅ RECON COMPLETE"
echo "--------------------------------------------------"
echo "📂 Output Folder:   $ABS_DIR"
echo "📄 Final File:      All_${DOMAIN}_IP_Range.txt"
echo "📊 Total Ranges:    $FINAL_COUNT"
echo "--------------------------------------------------"
