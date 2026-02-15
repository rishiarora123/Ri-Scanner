"""
Input validation and user-friendly error messages for Ri-Scanner Pro.
All validation functions return (is_valid: bool, message: str) tuples.
"""
import re
from typing import Tuple, List
import ipaddress


# User-friendly error messages
ERROR_MESSAGES = {
    # MongoDB errors
    "mongo_connection": "📡 Unable to connect to database. Please ensure MongoDB is running (run: brew services start mongodb-community)",
    "mongo_save_failed": "💾 Failed to save data to database. Please check MongoDB status.",
    
    # File upload errors
    "file_too_large": "📁 File is too large. Maximum size is 10MB.",
    "file_invalid_type": "📁 Invalid file type. Please upload a .txt, .xml, or .json file.",
    "file_empty": "📁 The uploaded file is empty. Please check the file and try again.",
    "file_not_selected": "📁 No file selected. Please choose a file to upload.",
    
    # Domain validation errors
    "domain_empty": "🌐 Please enter a domain name (e.g., example.com)",
    "domain_invalid": "🌐 Invalid domain format. Please use format: example.com (without http://)",
    "domain_too_long": "🌐 Domain name is too long. Maximum 253 characters.",
    
    # IP validation errors
    "ip_invalid": "🔢 Invalid IP address format. Use format: 192.168.1.1",
    "ip_range_invalid": "🔢 Invalid IP range format. Use format: 192.168.1.0/24 or 192.168.1.1-192.168.1.255",
    
    # ASN validation errors
    "asn_empty": "🏢 Please enter at least one ASN (e.g., AS15169 for Google)",
    "asn_invalid": "🏢 Invalid ASN format. Use format: AS15169 or 15169",
    
    # Scan configuration errors
    "scan_rate_invalid": "⚡ Scan speed must be between 100 and 100,000 packets per second.",
    "scan_already_running": "🔄 A scan is already in progress. Please wait for it to finish or stop it first.",
    
    # Permission errors
    "sudo_required": "🔒 This operation requires administrator access. Please run: sudo python3 main.py",
    
    # General errors
    "unknown_error": "❌ Something went wrong. Please try again or contact support.",
    "invalid_input": "⚠️ Invalid input. Please check your entry and try again.",
}


def validate_domain(domain: str) -> Tuple[bool, str]:
    """
    Validate domain name format.
    
    Args:
        domain: Domain name to validate
    
    Returns:
        (is_valid, message) tuple
    """
    if not domain or not domain.strip():
        return False, ERROR_MESSAGES["domain_empty"]
    
    domain = domain.strip().lower()
    
    # Remove common mistakes
    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
    
    if len(domain) > 253:
        return False, ERROR_MESSAGES["domain_too_long"]
    
    # Domain pattern: allows subdomains, main domain, and TLD
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if not re.match(pattern, domain):
        return False, ERROR_MESSAGES["domain_invalid"]
    
    return True, domain  # Return cleaned domain


def validate_ip_address(ip: str) -> Tuple[bool, str]:
    """
    Validate IP address format.
    
    Args:
        ip: IP address to validate
    
    Returns:
        (is_valid, message) tuple
    """
    try:
        ipaddress.ip_address(ip.strip())
        return True, ip.strip()
    except ValueError:
        return False, ERROR_MESSAGES["ip_invalid"]


def validate_ip_range(ip_range: str) -> Tuple[bool, str]:
    """
    Validate IP range or CIDR format.
    
    Args:
        ip_range: IP range (CIDR or range format)
    
    Returns:
        (is_valid, message) tuple
    """
    ip_range = ip_range.strip()
    
    # Try CIDR format first
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True, ip_range
    except ValueError:
        pass
    
    # Try range format (e.g., 192.168.1.1-192.168.1.255)
    if '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) == 2:
            valid_start, _ = validate_ip_address(parts[0])
            valid_end, _ = validate_ip_address(parts[1])
            if valid_start and valid_end:
                return True, ip_range
    
    return False, ERROR_MESSAGES["ip_range_invalid"]


def validate_asn_number(asn: str) -> Tuple[bool, str]:
    """
    Validate ASN format.
    
    Args:
        asn: ASN to validate (e.g., "AS15169" or "15169")
    
    Returns:
        (is_valid, normalized_asn) tuple
    """
    asn = asn.strip().upper()
    
    # Remove "AS" prefix if present
    if asn.startswith('AS'):
        asn_number = asn[2:]
    else:
        asn_number = asn
    
    # Check if it's a valid number
    if not asn_number.isdigit():
        return False, ERROR_MESSAGES["asn_invalid"]
    
    # Normalize to AS prefix format
    normalized = f"AS{asn_number}"
    return True, normalized


def validate_asn_list(asns_str: str) -> Tuple[bool, str, List[str]]:
    """
    Validate a comma/space-separated list of ASNs or IP/CIDR ranges.
    
    Args:
        asns_str: String containing ASNs or CIDRs separated by commas or spaces
    
    Returns:
        (is_valid, message, normalized_list) tuple
    """
    if not asns_str or not asns_str.strip():
        return False, ERROR_MESSAGES["asn_empty"], []
    
    # Split by commas or whitespace
    entries = re.split(r'[,\s]+', asns_str.strip())
    normalized = []
    
    for entry in entries:
        if not entry:
            continue
        
        # 1. Try as IP/CIDR entry
        is_ip_range, _ = validate_ip_range(entry)
        if is_ip_range:
            normalized.append(entry)
            continue
            
        # 2. Try as ASN entry
        valid_asn, result = validate_asn_number(entry)
        if valid_asn:
            normalized.append(result)
            continue
            
        return False, f"⚠️ Invalid entry: {entry}. Must be ASN (e.g., AS15169) or IP/CIDR (e.g., 1.1.1.0/24).", []
    
    if not normalized:
        return False, ERROR_MESSAGES["asn_empty"], []
    
    return True, f"✅ {len(normalized)} target(s) validated successfully", normalized


def validate_scan_rate(rate: str) -> Tuple[bool, str, int]:
    """
    Validate masscan rate parameter.
    
    Args:
        rate: Scan rate as string
    
    Returns:
        (is_valid, message, rate_int) tuple
    """
    try:
        rate_int = int(rate)
        if rate_int < 100 or rate_int > 100000:
            return False, ERROR_MESSAGES["scan_rate_invalid"], 10000
        return True, "Valid", rate_int
    except ValueError:
        return False, ERROR_MESSAGES["scan_rate_invalid"], 10000


def validate_file_upload(file) -> Tuple[bool, str]:
    """
    Validate uploaded file.
    
    Args:
        file: Flask file upload object
    
    Returns:
        (is_valid, message) tuple
    """
    if not file or file.filename == '':
        return False, ERROR_MESSAGES["file_not_selected"]
    
    # Check file extension
    allowed_extensions = {'txt', 'xml', 'json'}
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if ext not in allowed_extensions:
        return False, ERROR_MESSAGES["file_invalid_type"]
    
    # Check file size (read content length if available)
    if hasattr(file, 'content_length') and file.content_length:
        if file.content_length > 10 * 1024 * 1024:  # 10MB
            return False, ERROR_MESSAGES["file_too_large"]
    
    return True, "Valid"


def get_friendly_error(error_key: str, **kwargs) -> str:
    """
    Get user-friendly error message by key.
    
    Args:
        error_key: Error message key
        **kwargs: Optional format arguments
    
    Returns:
        Formatted error message
    """
    message = ERROR_MESSAGES.get(error_key, ERROR_MESSAGES["unknown_error"])
    
    if kwargs:
        try:
            return message.format(**kwargs)
        except KeyError:
            return message
    
    return message
