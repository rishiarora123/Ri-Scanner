import asyncio

class ScannerConfig:
    def __init__(
        self,
        ssl_port=443,
        mass_scan_results_file="masscanResults.txt",
        ips_file="ips_to_scan.txt",
        masscan_rate=10000,
        timeout=5,
        chunkSize=10000,
        MAX_CONCURRENT=1000,
        semaphore_limit=1000,
        ports=[80],
        protocols=["http://", "https://"],
        server_url="http://127.0.0.1:5000/insert",
    ):
        self.ssl_port = ssl_port
        self.mass_scan_results_file = mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        self.protocols = protocols
        self.server_url = server_url
        self.timeout = timeout
        self.chunkSize = chunkSize
        self.semaphore = asyncio.Semaphore(semaphore_limit)
        self.ports = ports
        self.MAX_CONCURRENT = MAX_CONCURRENT