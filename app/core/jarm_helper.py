"""
JARM/TLS Fingerprinting Helper Module

Provides TLS fingerprinting for identifying servers by their SSL/TLS configuration.
Uses a simplified cipher-based fingerprint approach for efficiency.
"""
import ssl
import socket
import mmh3


def get_jarm_hash(ip, port=443):
    """
    Get a TLS fingerprint hash for server identification.
    
    Uses the negotiated cipher suite, protocol version, and key bits
    to create a unique fingerprint for the server's TLS configuration.
    
    Args:
        ip: Target IP address
        port: Target port (default 443)
        
    Returns:
        Integer hash of the TLS fingerprint, or None on failure
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()
                # cipher returns (cipher_name, protocol_version, secret_bits)
                # Example: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
                fingerprint = f"{cipher[0]}|{cipher[1]}|{cipher[2]}"
                return mmh3.hash(fingerprint)
    except Exception:
        return None
