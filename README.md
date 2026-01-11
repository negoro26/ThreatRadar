# Threat Intelligence Dashboard

A vulnerability scanning and threat analysis platform built with Next.js. This tool aggregates data from VirusTotal, AbuseIPDB, URLScan.io, and URLHaus to provide security assessments of URLs and IP addresses.

![output](https://github.com/user-attachments/assets/d78d7dc5-2e62-4301-837e-80bbda7a2dc6)

## Features

- **Multi-Source Analysis**: VirusTotal, AbuseIPDB, URLScan.io, and URLHaus integration.
- **Global Safety Score**: Aggregated security score based on multiple indicators.
- **Live Analysis**: Screenshots and technology detection via URLScan.io.
- **Local Caching**: Results cached to optimize API usage.
- **History**: Local persistent scan history.

## Setup

### 1. Prerequisites

Obtain API keys for the following services:
- [VirusTotal](https://www.virustotal.com/gui/my-apikey)
- [AbuseIPDB](https://www.abuseipdb.com/account/api)
- [URLScan.io](https://urlscan.io/user/profile/)
- [URLHaus](https://urlhaus-api.abuse.ch/#urlinfo)

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/threat-intel-dashboard.git
cd threat-intel-dashboard

# Install dependencies
npm install
```

### 3. Environment Variables

Create a `.env.local` file:

```env
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
URLSCAN_API_KEY=your_urlscan_key
URLHAUS_API_KEY=your_urlhaus_key
```

### 4. Run

```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000).

## Deployment

```bash
npm run build
npm start
```

## Security Note

- Do not scan private/internal URLs containing sensitive tokens.
- Scans submitted to URLScan.io are set to `unlisted` by default.

## License

MIT
