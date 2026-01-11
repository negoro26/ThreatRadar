import './globals.css';
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Threat Intelligence Dashboard',
  description: 'Professional-grade vulnerability scanning and threat analysis platform',
  openGraph: {
    title: 'Threat Intelligence Dashboard',
    description: 'Comprehensive vulnerability scanning with VirusTotal, AbuseIPDB, URLScan, and URLHaus',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Threat Intelligence Dashboard',
    description: 'Professional-grade vulnerability scanning and threat analysis',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>{children}</body>
    </html>
  );
}
