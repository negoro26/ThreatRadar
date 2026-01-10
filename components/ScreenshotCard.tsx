'use client';

import { Monitor, AlertCircle } from 'lucide-react';
import { ThreatIntelligenceResult } from '@/app/actions/threat-intel';

interface ScreenshotCardProps {
  results: ThreatIntelligenceResult;
}

export function ScreenshotCard({ results }: ScreenshotCardProps) {
  const { urlScan, urlHaus, virusTotal, abuseIPDB, globalScore } = results;

  // Derive malicious status from ALL APIs
  const isMalicious =
    (urlScan?.verdict.malicious) ||
    (urlHaus?.query_status === 'ok' && urlHaus?.url_status === 'online') ||
    (virusTotal && virusTotal.malicious > 0) ||
    (abuseIPDB && abuseIPDB.abuseConfidenceScore > 80);

  // Use globalScore which already considers all APIs
  const displayScore = globalScore;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Monitor className="w-5 h-5 text-cyan-400" />
          Live Screenshot
        </h3>
        {isMalicious && (
          <div className="flex items-center gap-1 px-2 py-1 bg-rose-500/10 border border-rose-500/20 rounded-full">
            <AlertCircle className="w-3 h-3 text-rose-400" />
            <span className="text-xs text-rose-400 font-medium">Malicious</span>
          </div>
        )}
      </div>

      {urlScan?.screenshotUrl ? (
        <div className="relative w-full aspect-video bg-slate-800 rounded-lg overflow-hidden border border-slate-700">
          <img
            src={urlScan.screenshotUrl}
            alt="Page screenshot"
            className="w-full h-full object-cover"
          />
        </div>
      ) : (
        <div className="relative w-full aspect-video bg-slate-800 rounded-lg overflow-hidden border border-slate-700 flex items-center justify-center">
          <div className="text-center">
            <Monitor className="w-12 h-12 text-slate-600 mx-auto mb-2" />
            <p className="text-sm text-slate-500">No Screenshot Available</p>
          </div>
        </div>
      )}

      <div className="mt-4 grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs text-slate-400 mb-1">Global Score</p>
          <div className="flex items-baseline gap-2">
            <p className="text-2xl font-bold text-slate-300">
              {displayScore}
            </p>
            <span className="text-xs text-slate-500">/100</span>
          </div>
        </div>
        <div>
          <p className="text-xs text-slate-400 mb-1">Status</p>
          <p className={`text-sm font-medium ${isMalicious ? 'text-rose-400' : 'text-emerald-400'}`}>
            {isMalicious ? 'Malicious' : 'Clean'}
          </p>
        </div>
      </div>
    </div>
  );
}
