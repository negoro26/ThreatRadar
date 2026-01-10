# Threat Intelligence Dashboard

A professional-grade vulnerability scanning and threat analysis platform built with Next.js, featuring real-time data from VirusTotal, AbuseIPDB, and URLScan.io.

## Features

- **Comprehensive Threat Analysis**: Scan URLs and IP addresses across multiple threat intelligence sources
- **Global Safety Score**: Aggregated security score from multiple data sources
- **Live Screenshots**: Visual preview of scanned URLs via URLScan.io
- **Technology Detection**: Identify technologies used by target websites
- **Scan History**: Track your previous scans with localStorage
- **Dark Mode UI**: Cyber-security themed interface with emerald (safe) and rose (malicious) accents
- **Shimmer Loading States**: Fast, responsive UI with skeleton loaders
- **Parallel API Fetching**: Efficient data retrieval using Server Actions

## Tech Stack

- **Framework**: Next.js 13+ with App Router
- **Styling**: Tailwind CSS with custom dark theme
- **Icons**: Lucide React
- **UI Components**: shadcn/ui
- **API Integration**: Next.js Server Actions
- **Data Sources**:
  - VirusTotal API
  - AbuseIPDB API
  - URLScan.io API

## Getting Started

### Prerequisites

You'll need API keys from the following services (all have free tiers):

1. **VirusTotal**: [Get API Key](https://www.virustotal.com/gui/my-apikey)
2. **AbuseIPDB**: [Get API Key](https://www.abuseipdb.com/account/api)
3. **URLScan.io**: [Get API Key](https://urlscan.io/user/profile/)

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env.local` file in the root directory:
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   URLSCAN_API_KEY=your_urlscan_api_key_here
   ```

4. Run the development server:
   ```bash
   npm run dev
   ```

5. Open [http://localhost:3000](http://localhost:3000) in your browser

## Usage

1. Enter a URL (e.g., `example.com`) or IP address (e.g., `8.8.8.8`) in the search bar
2. Click "Scan" to initiate the threat analysis
3. View results including:
   - Global Safety Score (0-100)
   - VirusTotal detection statistics
   - AbuseIPDB abuse confidence score (for IPs)
   - URLScan.io screenshot and technologies (for URLs)
4. Access detailed raw data through the tabbed interface
5. Review past scans in the History sidebar

## Architecture

### Server Actions
- All API calls are handled through Next.js Server Actions to keep API keys secure
- Parallel fetching ensures optimal performance
- Graceful error handling for partial results

### Components
- `ThreatDashboard`: Main dashboard component with search and results
- `SafetyGauge`: Animated circular gauge for global safety score
- `ScreenshotCard`: Displays URLScan.io screenshot and verdict
- `ThreatDataTabs`: Tabbed interface for detailed raw data
- `LoadingShimmer`: Skeleton loader with shimmer animation

### Scoring Algorithm
The Global Safety Score is calculated by aggregating:
- VirusTotal detections (40% weight)
- AbuseIPDB confidence score (30% weight for IPs)
- URLScan.io verdict (30% weight for URLs)

## Security

- API keys are stored securely in environment variables
- Server Actions prevent API key exposure to clients
- No sensitive data is logged or stored persistently
- History is stored locally in browser localStorage

## Threat Level Classification

- **90-100**: Safe (Emerald)
- **60-89**: Low Risk (Green)
- **40-59**: Moderate (Yellow)
- **20-39**: High Risk (Orange)
- **0-19**: Critical (Rose)

## API Rate Limits

Be aware of the free tier rate limits:
- **VirusTotal**: 4 requests/minute, 500 requests/day
- **AbuseIPDB**: 1,000 requests/day
- **URLScan.io**: Variable based on plan

## License

This project is for educational and security research purposes.
