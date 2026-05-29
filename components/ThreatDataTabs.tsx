'use client';

import { useState } from 'react';
import { Database, Shield, AlertTriangle, Globe } from 'lucide-react';
import { ThreatIntelligenceResult } from '@/app/actions/threat-intel';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';

interface ThreatDataTabsProps {
  results: ThreatIntelligenceResult;
}

export function ThreatDataTabs({ results }: ThreatDataTabsProps) {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <div className="p-4 bg-card border border-border rounded-md">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted mb-3 flex items-center gap-1.5">
        <Database className="w-4 h-4" />
        Detailed Analysis
      </h3>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="bg-secondary border border-border w-full justify-start overflow-x-auto rounded-md p-0.5 mb-2 max-w-full">
          <TabsTrigger
            value="overview"
            className="data-[state=active]:bg-card data-[state=active]:text-primary rounded-sm text-xs whitespace-nowrap"
          >
            Overview
          </TabsTrigger>
          {results.virusTotal && (
            <TabsTrigger
              value="virustotal"
              className="data-[state=active]:bg-card data-[state=active]:text-primary rounded-sm text-xs whitespace-nowrap"
            >
              <Shield className="w-3.5 h-3.5 mr-1" />
              VirusTotal
            </TabsTrigger>
          )}
          {results.abuseIPDB && (
            <TabsTrigger
              value="abuseipdb"
              className="data-[state=active]:bg-card data-[state=active]:text-primary rounded-sm text-xs whitespace-nowrap"
            >
              <AlertTriangle className="w-3.5 h-3.5 mr-1" />
              AbuseIPDB
            </TabsTrigger>
          )}
          {results.urlScan && (
            <TabsTrigger
              value="urlscan"
              className="data-[state=active]:bg-card data-[state=active]:text-primary rounded-sm text-xs whitespace-nowrap"
            >
              <Globe className="w-3.5 h-3.5 mr-1" />
              URLScan
            </TabsTrigger>
          )}
          {results.urlHaus && (
            <TabsTrigger
              value="urlhaus"
              className="data-[state=active]:bg-card data-[state=active]:text-primary rounded-sm text-xs whitespace-nowrap"
            >
              <AlertTriangle className="w-3.5 h-3.5 mr-1" />
              URLHaus
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="overview" className="mt-3">
          <div className="space-y-3">
            <div className="p-4 bg-secondary/50 rounded-md border border-border">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-primary mb-3">Scan Summary</h4>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <div>
                  <p className="text-[11px] text-muted">Target</p>
                  <p className="font-mono-data text-sm text-foreground break-all">{results.target}</p>
                </div>
                <div>
                  <p className="text-[11px] text-muted">Type</p>
                  <p className="font-mono-data text-sm text-foreground uppercase">{results.type}</p>
                </div>
                <div>
                  <p className="text-[11px] text-muted">Global Score</p>
                  <p className="font-mono-data text-sm font-bold text-primary">{results.globalScore}/100</p>
                </div>
                <div>
                  <p className="text-[11px] text-muted">Timestamp</p>
                  <p className="font-mono-data text-sm text-foreground">
                    {new Date(results.timestamp).toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] text-muted">Data Sources</p>
                  <p className="font-mono-data text-sm text-foreground">
                    {[
                      results.virusTotal && 'VT',
                      results.abuseIPDB && 'AIPDB',
                      results.urlScan && 'URLScan',
                      results.urlHaus && 'URLHaus',
                    ]
                      .filter(Boolean)
                      .join(', ')}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] text-muted">Status</p>
                  <p className="font-mono-data text-sm text-foreground">
                    {results.success ? 'Complete' : 'Partial/Failed'}
                  </p>
                </div>
              </div>
            </div>

            {results.errors && results.errors.length > 0 && (
              <div className="p-4 bg-warning/5 rounded-md border border-warning/20">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-warning mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Warnings
                </h4>
                <ul className="list-disc list-inside space-y-1">
                  {results.errors.map((error, idx) => (
                    <li key={idx} className="font-mono-data text-xs text-destructive">
                      {error}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </TabsContent>

        {results.virusTotal && (
          <TabsContent value="virustotal" className="mt-3">
            <div className="p-4 bg-secondary/50 rounded-md border border-border w-full overflow-hidden">
              <pre className="font-mono-data text-xs text-foreground overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.virusTotal, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}

        {results.abuseIPDB && (
          <TabsContent value="abuseipdb" className="mt-3">
            <div className="p-4 bg-secondary/50 rounded-md border border-border w-full overflow-hidden">
              <pre className="font-mono-data text-xs text-foreground overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.abuseIPDB, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}

        {results.urlScan && (
          <TabsContent value="urlscan" className="mt-3">
            <div className="p-4 bg-secondary/50 rounded-md border border-border w-full overflow-hidden">
              <pre className="font-mono-data text-xs text-foreground overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.urlScan, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}

        {results.urlHaus && (
          <TabsContent value="urlhaus" className="mt-3">
            <div className="p-4 bg-secondary/50 rounded-md border border-border w-full overflow-hidden">
              <pre className="font-mono-data text-xs text-foreground overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.urlHaus, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
