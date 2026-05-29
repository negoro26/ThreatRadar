"use client";

import { Monitor } from "lucide-react";
import { cn } from "@/lib/utils";

interface ScreenshotPreviewProps {
  screenshotUrl?: string;
  domain: string;
  className?: string;
}

export function ScreenshotPreview({ screenshotUrl, domain, className }: ScreenshotPreviewProps) {
  return (
    <div className={cn("w-full", className)}>
      {screenshotUrl ? (
        <div className="relative w-full aspect-video bg-background border border-border rounded-sm overflow-hidden">
          {/* §3.3 — sharp corners, 1px border. Never object-cover; preserve aspect ratio with letterboxing */}
          <img
            src={screenshotUrl}
            alt={`Screenshot of ${domain}`}
            className="w-full h-full object-contain bg-black"
          />
        </div>
      ) : (
        <div className="relative w-full aspect-video bg-card border border-dashed border-border rounded-sm flex items-center justify-center">
          <div className="text-center">
            <Monitor className="w-5 h-5 text-muted mx-auto mb-2" />
            <p className="font-mono-data text-sm text-muted">{domain}</p>
          </div>
        </div>
      )}
    </div>
  );
}
