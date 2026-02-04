# Ri-Scanner Pro

**Professional Security Reconnaissance Tool** for discovering hidden infrastructure, extracting SSL certificates, and identifying technologies across IP ranges.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- 🔍 **Full Recon Pipeline**: Subdomain discovery → IP resolution → ASN expansion → Port scanning → Content discovery
- ⚡ **High-Speed Scanning**: Parallel Masscan chunking with real-time progress tracking
- 🔐 **SSL Certificate Extraction**: Async certificate fetching with Common Name extraction
- 🛡️ **Technology Detection**: Automatic detection of web technologies, frameworks, and WAFs
- 📊 **Live Dashboard**: Real-time scan progress, logs, and results search
- 🔖 **Fingerprinting**: Favicon hash (MMH3) and JARM TLS fingerprinting

## Prerequisites

- Python 3.9+
- MongoDB (running locally or remote)
- Masscan (requires sudo)
- Subfinder (for Full Recon mode)

### macOS Installation

```bash
# Install dependencies
brew install masscan subfinder

# Start MongoDB
brew services start mongodb-community
```

### Linux Installation

```bash
# Install Masscan
sudo apt install masscan

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install MongoDB
sudo apt install mongodb
sudo systemctl start mongodb
```

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ri-scanner.git
cd ri-scanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env with your settings
```

## Usage

```bash
# Start the scanner (requires sudo for Masscan)
sudo python main.py
```

Open your browser to **http://127.0.0.1:5000**

### Scan Modes

1. **Full Recon**: Enter a domain to automatically discover subdomains, resolve IPs, expand ASN ranges, and scan for open ports.

2. **From Masscan Result**: Upload an existing Masscan output file (-oH format) to extract domains and probe HTTP/HTTPS.

3. **From IP List**: Upload a file containing IP ranges or CIDRs to scan directly.

## Configuration

Create a `.env` file or edit `app/__init__.py`:

```bash
MONGO_URI=mongodb://localhost:27017/
MASSCAN_RATE=10000
MAX_CONCURRENT=1000
TIMEOUT=5
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page |
| `/dashboard` | GET | Scan dashboard |
| `/start_scan` | POST | Start a new scan |
| `/stop_scan` | POST | Stop running scan |
| `/get_status` | GET | Get scan progress |
| `/get_logs` | GET | Get live logs |
| `/search/title` | GET | Search results by title |
| `/export` | POST | Export results to JSON |

## Project Structure

```
ri-scanner/
├── main.py              # Application entry point
├── requirements.txt     # Python dependencies
├── app/
│   ├── __init__.py      # Flask app factory
│   ├── routes.py        # API endpoints
│   ├── core/
│   │   ├── config.py    # Scanner configuration
│   │   ├── core.py      # Main scan logic
│   │   ├── ssl_helper.py    # SSL certificate fetching
│   │   ├── http_helper.py   # HTTP probing & tech detection
│   │   ├── jarm_helper.py   # TLS fingerprinting
│   │   └── utils.py     # Utility functions
│   ├── static/css/      # Stylesheets
│   └── templates/       # HTML templates
└── Tmp/                 # Scan output directory
```

## Technologies Detected

The scanner can identify:

- **Web Servers**: Nginx, Apache, IIS
- **Frameworks**: React, Vue.js, Angular, WordPress
- **Languages**: PHP, ASP.NET, Express.js
- **WAFs**: Cloudflare, AWS CloudFront, Akamai, Imperva, Sucuri

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any systems you do not own.
