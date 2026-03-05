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
    <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-800/60 rounded-3xl p-6 sm:p-8 shadow-2xl hover:border-slate-700/50 transition-colors w-full h-full flex flex-col">
      <div className="flex items-center justify-between mb-5">
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
        <div className="relative w-full aspect-video bg-slate-900/50 rounded-2xl overflow-hidden border border-slate-700/50 shadow-inner group">
          <img
            src={urlScan.screenshotUrl}
            alt="Page screenshot"
            className="w-full h-full object-cover group-hover:scale-[1.02] transition-transform duration-500"
          />
        </div>
      ) : (
        <div className="relative w-full aspect-video bg-slate-900/30 rounded-2xl overflow-hidden border border-dashed border-slate-700/50 flex items-center justify-center">
          <div className="text-center p-6">
            <Monitor className="w-12 h-12 text-slate-700 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-500">No Screenshot Available</p>
          </div>
        </div>
      )}

      <div className="mt-6 grid grid-cols-2 gap-4 mt-auto pt-6 border-t border-slate-800/60">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Global Score</p>
          <div className="flex items-baseline gap-1.5">
            <p className="text-3xl font-bold text-slate-200">
              {displayScore}
            </p>
            <span className="text-sm font-medium text-slate-600">/100</span>
          </div>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Status</p>
          <p className={`text-base font-bold tracking-wide ${isMalicious ? 'text-rose-400' : 'text-emerald-400'}`}>
            {isMalicious ? 'MALICIOUS' : 'CLEAN'}
          </p>
        </div>
      </div>
    </div>
  );
}
