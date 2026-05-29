"use client";

import { ThreatIntelligenceResult } from "@/app/actions/threat-intel";
import { SafetyScoreBadge } from "./SafetyScoreBadge";
import { TechStackList } from "./TechStackList";
import { ScreenshotPreview } from "./ScreenshotPreview";
import { cn } from "@/lib/utils";

interface ScanResultCardProps {
  results: ThreatIntelligenceResult;
  className?: string;
}

export function ScanResultCard({ results, className }: ScanResultCardProps) {
  const { urlScan } = results;
  const domain = urlScan?.page.domain || new URL(results.target).hostname;

  return (
    <div
      className={cn(
        "grid grid-cols-1 md:grid-cols-[40%_1fr] gap-4 p-4 bg-card border border-border rounded-md",
        className
      )}
    >
      {/* Left: Screenshot */}
      <div className="flex flex-col gap-3">
        <ScreenshotPreview
          screenshotUrl={urlScan?.screenshotUrl}
          domain={domain}
        />
        <div className="flex items-center gap-3">
          <SafetyScoreBadge score={results.globalScore} />
        </div>
      </div>

      {/* Right: Metadata */}
      <div className="flex flex-col gap-4">
        <div className="space-y-2">
          <div className="flex items-baseline gap-2">
            <span className="text-xs text-muted uppercase tracking-wider">Domain</span>
            <span className="font-mono-data text-sm text-foreground">{domain}</span>
          </div>
          {urlScan?.page.server && (
            <div className="flex items-baseline gap-2">
              <span className="text-xs text-muted uppercase tracking-wider">Server</span>
              <span className="font-mono-data text-sm text-foreground">{urlScan.page.server}</span>
            </div>
          )}
          {urlScan?.page.country && (
            <div className="flex items-baseline gap-2">
              <span className="text-xs text-muted uppercase tracking-wider">Country</span>
              <span className="font-mono-data text-sm text-foreground">{urlScan.page.country}</span>
            </div>
          )}
        </div>

        {/* Tech Stack */}
        {urlScan && urlScan.technologies.length > 0 && (
          <div>
            <h4 className="text-xs text-muted uppercase tracking-wider mb-2">Technologies</h4>
            <TechStackList technologies={urlScan.technologies} />
          </div>
        )}
      </div>
    </div>
  );
}
