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
    <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-800/60 rounded-3xl p-6 sm:p-8 shadow-2xl hover:border-slate-700/50 transition-colors mt-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Database className="w-5 h-5 text-cyan-400" />
        Detailed Analysis
      </h3>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="bg-slate-800/50 border border-slate-700/50 w-full justify-start overflow-x-auto rounded-xl p-1 mb-2 max-w-full">
          <TabsTrigger
            value="overview"
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-emerald-400 rounded-lg whitespace-nowrap"
          >
            Overview
          </TabsTrigger>
          {results.virusTotal && (
            <TabsTrigger
              value="virustotal"
              className="data-[state=active]:bg-slate-700 data-[state=active]:text-emerald-400 rounded-lg whitespace-nowrap"
            >
              <Shield className="w-4 h-4 mr-2" />
              VirusTotal
            </TabsTrigger>
          )}
          {results.abuseIPDB && (
            <TabsTrigger
              value="abuseipdb"
              className="data-[state=active]:bg-slate-700 data-[state=active]:text-emerald-400 rounded-lg whitespace-nowrap"
            >
              <AlertTriangle className="w-4 h-4 mr-2" />
              AbuseIPDB
            </TabsTrigger>
          )}
          {results.urlScan && (
            <TabsTrigger
              value="urlscan"
              className="data-[state=active]:bg-slate-700 data-[state=active]:text-emerald-400 rounded-lg whitespace-nowrap"
            >
              <Globe className="w-4 h-4 mr-2" />
              URLScan
            </TabsTrigger>
          )}
          {results.urlHaus && (
            <TabsTrigger
              value="urlhaus"
              className="data-[state=active]:bg-slate-700 data-[state=active]:text-emerald-400 rounded-lg whitespace-nowrap"
            >
              <AlertTriangle className="w-4 h-4 mr-2" />
              URLHaus
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <div className="space-y-4">
            <div className="p-5 sm:p-6 bg-slate-800/30 backdrop-blur-md rounded-2xl border border-slate-700/50">
              <h4 className="text-sm font-semibold mb-4 text-emerald-400">Scan Summary</h4>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div>
                  <p className="text-xs text-slate-400">Target</p>
                  <p className="text-sm text-slate-300 break-all">{results.target}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Type</p>
                  <p className="text-sm text-slate-300 uppercase">{results.type}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Global Score</p>
                  <p className="text-sm font-bold text-emerald-400">{results.globalScore}/100</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Timestamp</p>
                  <p className="text-sm text-slate-300">
                    {new Date(results.timestamp).toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-slate-400">Data Sources</p>
                  <p className="text-sm text-slate-300">
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
                  <p className="text-xs text-slate-400">Status</p>
                  <p className="text-sm text-slate-300">
                    {results.success ? 'Complete' : 'Partial/Failed'}
                  </p>
                </div>
              </div>
            </div>

            {results.errors && results.errors.length > 0 && (
              <div className="p-5 sm:p-6 bg-yellow-500/10 rounded-2xl border border-yellow-500/20 backdrop-blur-sm">
                <h4 className="text-sm font-semibold mb-3 text-yellow-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Warnings
                </h4>
                <ul className="list-disc list-inside space-y-1">
                  {results.errors.map((error, idx) => (
                    <li key={idx} className="text-xs text-slate-400">
                      {error}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </TabsContent>

        {results.virusTotal && (
          <TabsContent value="virustotal" className="mt-4">
            <div className="p-5 bg-slate-800/30 backdrop-blur-md rounded-2xl border border-slate-700/50 w-full overflow-hidden">
              <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.virusTotal, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}

        {results.abuseIPDB && (
          <TabsContent value="abuseipdb" className="mt-4">
            <div className="p-5 bg-slate-800/30 backdrop-blur-md rounded-2xl border border-slate-700/50 w-full overflow-hidden">
              <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.abuseIPDB, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}

        {results.urlScan && (
          <TabsContent value="urlscan" className="mt-4">
            <div className="p-5 bg-slate-800/30 backdrop-blur-md rounded-2xl border border-slate-700/50 w-full overflow-hidden">
              <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.urlScan, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}

        {results.urlHaus && (
          <TabsContent value="urlhaus" className="mt-4">
            <div className="p-5 bg-slate-800/30 backdrop-blur-md rounded-2xl border border-slate-700/50 w-full overflow-hidden">
              <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-words max-h-[500px] overflow-y-auto custom-scrollbar">
                {JSON.stringify(results.urlHaus, null, 2)}
              </pre>
            </div>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
