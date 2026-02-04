"""
SSL Certificate Fetching Helper Module

Provides optimized async SSL certificate extraction from IP addresses.
Uses native asyncio for maximum performance.
"""
import asyncio
import ssl
from typing import Tuple, Optional
from OpenSSL import crypto
from .utils import log_to_server


# Pre-create SSL context for reuse (significant performance boost)
_SHARED_SSL_CONTEXT: Optional[ssl.SSLContext] = None


def get_ssl_context() -> ssl.SSLContext:
    """Get a shared SSL context for connection reuse."""
    global _SHARED_SSL_CONTEXT
    if _SHARED_SSL_CONTEXT is None:
        _SHARED_SSL_CONTEXT = ssl.create_default_context()
        _SHARED_SSL_CONTEXT.check_hostname = False
        _SHARED_SSL_CONTEXT.verify_mode = ssl.CERT_NONE
        # Optimize for speed
        _SHARED_SSL_CONTEXT.set_ciphers('DEFAULT@SECLEVEL=1')
    return _SHARED_SSL_CONTEXT


async def fetch_certificate(
    ip: str, 
    config, 
    ssl_context: Optional[ssl.SSLContext] = None
) -> Tuple[str, str]:
    """
    Fetch SSL certificate from an IP address and extract the Common Name.
    
    Args:
        ip: Target IP address to connect to
        config: ScannerConfig with port and timeout settings
        ssl_context: Optional pre-created SSL context for reuse
        
    Returns:
        Tuple of (ip, common_name). Common name is empty string on failure.
    """
    try:
        ctx = ssl_context if ssl_context else get_ssl_context()
        
        # Open connection asynchronously (Much faster than to_thread)
        conn = asyncio.open_connection(ip, config.ssl_port, ssl=ctx)
        reader, writer = await asyncio.wait_for(conn, timeout=config.timeout)

        # Get the certificate in binary form
        ssl_obj = writer.get_extra_info('ssl_object')
        if ssl_obj is None:
            writer.close()
            await writer.wait_closed()
            return ip, ""
            
        cert_bin = ssl_obj.getpeercert(binary_form=True)
        
        # Close connection immediately - don't wait for graceful close
        writer.close()
        # Use create_task to not block on close
        asyncio.create_task(_safe_close(writer))

        # Parse with OpenSSL
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        subject = x509.get_subject()
        common_name = subject.CN or ""
        
        return ip, common_name

    except asyncio.TimeoutError:
        # Silent timeout - very common, don't log
        return ip, ""
    except ConnectionRefusedError:
        # Connection refused is expected for non-HTTPS hosts
        return ip, ""
    except OSError as e:
        # Network errors (no route, connection reset etc)
        # Only log if debug needed
        pass
    except crypto.Error as e:
        # Certificate parsing error
        log_to_server(f"SSL Parse Error for {ip}: {str(e)}")
    except Exception as e:
        # Unexpected errors - log for debugging
        log_to_server(f"Unexpected SSL Error for {ip}: {str(e)}")
    
    return ip, ""


async def _safe_close(writer: asyncio.StreamWriter) -> None:
    """Safely close a StreamWriter without blocking."""
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass


async def fetch_certificates_batch(
    ips: list, 
    config, 
    ssl_context: Optional[ssl.SSLContext] = None
) -> list:
    """
    Fetch certificates from multiple IPs concurrently.
    
    Args:
        ips: List of IP addresses to scan
        config: ScannerConfig with settings
        ssl_context: Optional shared SSL context
        
    Returns:
        List of (ip, common_name) tuples
    """
    ctx = ssl_context if ssl_context else get_ssl_context()
    tasks = [fetch_certificate(ip, config, ctx) for ip in ips]
    return await asyncio.gather(*tasks, return_exceptions=False)