# 🛡️ ThreatRadar
**Professional-grade Threat Intelligence & Vulnerability Scanning Dashboard**

ThreatRadar is a high-performance security platform built with Next.js 15 and Tailwind CSS 4. It aggregates real-time data from industry-leading security sources to provide a unified risk assessment for URLs and IP addresses.

![ThreatRadar Dashboard](https://github.com/user-attachments/assets/d78d7dc5-2e62-4301-837e-80bbda7a2dc6)

## 🚀 Features

- **Multi-Source Aggregation**: Integrated with VirusTotal, AbuseIPDB, URLScan.io, and URLHaus.
- **Asynchronous Deep Scanning**: Utilizes a dual-phase scanning approach for instant results followed by deep active analysis (URLScan).
- **Intelligent Scoring**: Global safety score calculated using weighted indicators from all sources.
- **Visual Intelligence**: Live screenshots and technology stack detection for scanned targets.
- **Privacy First**: Scans are submitted as `unlisted` to maintaining confidentiality.
- **Technical SEO Optimized**: Built-in JSON-LD structured data, dynamic sitemaps, and optimized metadata for maximum discoverability.

## 🛠️ Tech Stack

- **Framework**: [Next.js 15](https://nextjs.org/) (App Router)
- **Styling**: [Tailwind CSS 4](https://tailwindcss.com/)
- **Components**: Radix UI & Lucide Icons
- **Language**: TypeScript
- **State Management**: React Hooks & Local Storage Caching

## 🏁 Getting Started

### 1. Prerequisites

Obtain API keys from the following providers:
- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [URLScan.io](https://urlscan.io/)
- [URLHaus](https://urlhaus.abuse.ch/)

### 2. Installation

```bash
git clone https://github.com/negoro26/ThreatRadar.git
cd ThreatRadar
npm install
```

### 3. Environment Setup

Create a `.env.local` file in the root directory:

```env
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
URLSCAN_API_KEY=your_key
URLHAUS_API_KEY=your_key
```

### 4. Development

```bash
npm run dev
```

## 📈 Search Engine Optimization (SEO)

ThreatRadar is pre-configured for discoverability:
- **Dynamic Sitemap**: Automatically generated at `/sitemap.xml`.
- **Robots.txt**: Optimized for search engine crawlers.
- **Structured Data**: Includes Schema.org `SoftwareApplication` markup for rich search results.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

Developed with ❤️ by [negoro26](https://github.com/negoro26)
