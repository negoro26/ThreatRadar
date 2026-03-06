import './globals.css';
import type { Metadata } from 'next';
import Script from 'next/script';
import { Inter } from 'next/font/google';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'ThreatRadar | Professional Threat Intelligence & Vulnerability Scanning',
  description: 'Real-time vulnerability scanning and threat analysis. Aggregate data from VirusTotal, AbuseIPDB, URLScan, and URLHaus in one unified dashboard.',
  keywords: ['threat intelligence', 'vulnerability scanner', 'cybersecurity dashboard', 'ip reputation', 'malware analysis', 'url scanner'],
  authors: [{ name: 'ThreatRadar Team' }],
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  openGraph: {
    title: 'ThreatRadar | Professional Threat Intelligence',
    description: 'Empower your security workflow with aggregated threat intelligence from industry-leading sources.',
    url: 'https://threat-radar-pearl.vercel.app/',
    siteName: 'ThreatRadar',
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ThreatRadar | Real-Time Threat Intelligence',
    description: 'Professional-grade vulnerability scanning and threat analysis platform.',
    creator: '@threatradar',
  },
  category: 'technology',
  alternates: {
    canonical: 'https://threat-radar-pearl.vercel.app/',
  },
};

export const viewport = {
  themeColor: '#10b981', // Emerald-500 matching the brand
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        {children}
        <Script id="structured-data" type="application/ld+json" strategy="afterInteractive">
          {JSON.stringify({
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            "name": "ThreatRadar",
            "operatingSystem": "Web",
            "applicationCategory": "SecurityApplication",
            "description": "Professional-grade vulnerability scanning and threat analysis platform aggregating data from VirusTotal, AbuseIPDB, URLScan, and URLHaus.",
            "offers": {
              "@type": "Offer",
              "price": "0",
              "priceCurrency": "USD"
            },
            "author": {
              "@type": "Organization",
              "name": "ThreatRadar"
            }
          })}
        </Script>
      </body>
    </html>
  );
}
