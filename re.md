# 🔍 Enhanced Server Reconnaissance Scanner

A comprehensive server reconnaissance and security scanning tool with both CLI and Web interface.

## Features

### CLI Scanner
- **Passive Reconnaissance**: IP discovery, DNS records, SSL certificates, geolocation
- **Active Scanning**: Port scanning, service detection, banner grabbing
- **Web Probing**: Technology detection (65+ technologies), security headers, endpoint discovery
- **SSL/TLS Analysis**: Protocol support, cipher suites, security grading (A+ to C)
- **Local Server Info**: System details, listening ports, network interfaces

### Web Interface
- Beautiful dark-themed UI
- Real-time scan execution
- Interactive results dashboard
- Scan history with PostgreSQL storage

## Quick Start

### CLI Only (Standalone)

```bash
# Navigate to package
cd scanner-package

# Make scanner executable
chmod +x scanner.py

# Run a scan
python3 scanner.py localhost

# Save results to file
python3 scanner.py localhost -o results.json
```

### Full Web Application

```bash
# Install Node.js dependencies
npm install

# Install Python dependencies (optional, scanner uses stdlib)
pip3 install -r requirements.txt

# Setup database
npx drizzle-kit push

# Start development server
npm run dev

# Open http://localhost:3000
```

## CLI Usage

```bash
# Full scan
python3 scanner.py localhost

# Passive OSINT only
python3 scanner.py example.com --passive-only

# Active scan with specific ports
python3 scanner.py 127.0.0.1 --active-only --ports 80,443,8080

# Local server information
python3 scanner.py localhost --local

# Custom settings
python3 scanner.py localhost --timeout 10 --threads 100 --verbose

# Output to file
python3 scanner.py localhost -o scan_results.json
```

## Technology Detection

The scanner identifies 65+ technologies including:

**Web Servers**: Apache, Nginx, IIS, LiteSpeed, Caddy, Tomcat, Gunicorn

**Frameworks**: Express.js, Django, Flask, Rails, Laravel, Spring Boot, ASP.NET, Next.js, Nuxt, React, Vue, Angular

**CMS**: WordPress, Joomla, Drupal, Magento, Shopify

**Cloud/CDN**: Cloudflare, AWS, GCP, Azure, Fastly, Akamai, Vercel, Netlify

**Security**: WAF, Incapsula, Sucuri, ModSecurity, F5 BIG-IP

## API Endpoints (Web App)

### POST /api/scan
```json
{
  "target": "localhost",
  "scanType": "full|passive|active|local",
  "ports": "80,443,8080",
  "timeout": 5,
  "threads": 50
}
```

### GET /api/scan?id=1
Get scan results by ID.

### GET /api/scan?target=localhost&limit=10
Get scans for specific target.

## Security Notice

⚠️ **This tool is for authorized security testing only.**

- Active scanning is restricted to localhost by default in the web interface
- Always obtain proper authorization before scanning any system
- Use responsibly and in compliance with applicable laws

## File Structure

```
scanner-package/
├── scanner.py              # Main Python scanner (CLI)
├── requirements.txt        # Python dependencies
├── run.sh                  # Quick run script
├── README.md               # This file
├── web-app/                # Web application
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx    # Frontend UI
│   │   │   └── api/
│   │   │       └── scan/   # API routes
│   │   └── db/
│   │       └── schema.ts   # Database schema
│   ├── package.json
│   └── ...
└── standalone.html         # Simple HTML interface (no build needed)
```

## License

MIT License - Use responsibly for authorized security testing only.
