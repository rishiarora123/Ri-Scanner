import asyncio
import ssl
from OpenSSL import crypto
from .utils import log_to_server

async def fetch_certificate(ip, config, ssl_context=None):
    try:
        if ssl_context is None:
            # Create a default SSL context that ignores hostname checking (since we are scanning IPs)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl_context

        # Open connection asynchronously (Much faster than to_thread)
        conn = asyncio.open_connection(ip, config.ssl_port, ssl=ctx)
        reader, writer = await asyncio.wait_for(conn, timeout=config.timeout)

        # Get the certificate in binary form
        ssl_obj = writer.get_extra_info('ssl_object')
        cert_bin = ssl_obj.getpeercert(binary_form=True)
        
        # Close connection immediately
        writer.close()
        await writer.wait_closed()

        # Parse with OpenSSL
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        subject = x509.get_subject()
        common_name = subject.CN
        
        return ip, common_name

    except Exception as e:
        # Log error to dashboard verbose logs only, NOT terminal
        log_to_server(f"Error for {ip}: {str(e)}")

    # If we get to the line below, there will be timeout so ip did not response in that case return None and we wont process these ips with none
    return ip, ""