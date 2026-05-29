~"use client";

import { useState, useEffect, useRef } from "react";
import { Search, Shield, AlertTriangle, History, X, Loader2, Globe } from "lucide-react";
import {
  scanTargetFast,
  scanURLScanAsync,
  ThreatIntelligenceResult,
} from "@/app/actions/threat-intel";
import { calculateGlobalScore } from "@/lib/scoring";
import { SafetyScoreBadge } from "./dashboard/SafetyScoreBadge";
import { ScanResultCard } from "./dashboard/ScanResultCard";
import { ThreatDataTabs } from "./ThreatDataTabs";
import { LoadingShimmer } from "./LoadingShimmer";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

interface SearchHistory extends ThreatIntelligenceResult { }

export function ThreatDashboard() {
  const [searchInput, setSearchInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [isLoadingURLScan, setIsLoadingURLScan] = useState(false);
  const [results, setResults] = useState<ThreatIntelligenceResult | null>(null);
  const [history, setHistory] = useState<SearchHistory[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const urlScanAbortRef = useRef<boolean>(false);

  useEffect(() => {
    const savedHistory = localStorage.getItem("threat-scan-history");
    if (savedHistory) {
      setHistory(JSON.parse(savedHistory));
    }
  }, []);

  const saveToHistory = (result: ThreatIntelligenceResult) => {
    const newEntry: SearchHistory = result;

    const filteredHistory = history.filter((h) => h.target !== result.target);

    const updatedHistory = [newEntry, ...filteredHistory].slice(0, 20);
    setHistory(updatedHistory);
    localStorage.setItem("threat-scan-history", JSON.stringify(updatedHistory));
  };

  const handleScan = async (target?: string) => {
    const targetToScan = target || searchInput;
    if (!targetToScan.trim()) return;

    // Abort any in-flight URLScan from a previous scan
    urlScanAbortRef.current = true;

    // Normalize the target for cache comparison — cached entries store
    // the cleaned URL (e.g. "https://google.com"), not raw input ("google.com")
    let normalizedTarget = targetToScan.trim();
    if (
      !normalizedTarget.startsWith("http://") &&
      !normalizedTarget.startsWith("https://") &&
      !/^\d{1,3}(\.\d{1,3}){3}$/.test(normalizedTarget)
    ) {
      normalizedTarget = "https://" + normalizedTarget;
    }

    const cachedResult = history.find((h) => h.target === normalizedTarget);

    const CACHE_DURATION = 60 * 60 * 1000;

    if (cachedResult) {
      const isFresh = Date.now() - cachedResult.timestamp < CACHE_DURATION;

      if (isFresh) {
        console.log("HIT: Loading result from cache");
        setResults(cachedResult);
        setIsLoadingURLScan(false);
        return;
      } else {
        console.log("Cache expired. Calling API");
      }
    }

    setIsScanning(true);
    setIsLoadingURLScan(false);
    setResults(null);

    try {
      // Phase 1: Fast scan (VirusTotal, AbuseIPDB, URLHaus) — ~1 second
      const fastResult = await scanTargetFast(targetToScan);
      setResults(fastResult);
      setIsScanning(false);

      if (fastResult.success) {
        saveToHistory(fastResult);
      }

      // Use the cleaned target from the server result (e.g. "https://google.com")
      // instead of raw input (e.g. "google.com") so comparisons match
      const cleanedTarget = fastResult.target;

      // Phase 2: URLScan in the background (only for URL targets)
      if (fastResult.success && fastResult.type === "url") {
        setIsLoadingURLScan(true);
        urlScanAbortRef.current = false;

        // Fire and forget — this runs independently
        scanURLScanAsync(cleanedTarget).then((urlScanData) => {
          // If user started a new scan in the meantime, discard this result
          if (urlScanAbortRef.current) return;

          setIsLoadingURLScan(false);

          if (urlScanData) {
            // Merge URLScan data into existing results and recalculate score
            setResults((prev) => {
              if (!prev || prev.target !== cleanedTarget) return prev;

              const newScore = calculateGlobalScore(
                prev.virusTotal || null,
                prev.abuseIPDB || null,
                urlScanData,
                prev.urlHaus || null,
              );

              const updated: ThreatIntelligenceResult = {
                ...prev,
                urlScan: urlScanData,
                globalScore: newScore,
              };

              // Update cache with complete data
              saveToHistory(updated);
              return updated;
            });
          }
        }).catch((error) => {
          console.error("URLScan background error:", error);
          if (!urlScanAbortRef.current) {
            setIsLoadingURLScan(false);
          }
        });
      }
    } catch (error) {
      console.error("Scan error:", error);
      setIsScanning(false);
    }
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("threat-scan-history");
  };

  const getRelativeTime = (timestamp: number) => {
    const diff = Date.now() - timestamp;
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  return (
    <div className="min-h-screen bg-background text-foreground overflow-x-hidden relative">
      <div className="flex w-full">
        <div
          className={`flex-1 min-w-0 flex flex-col min-h-screen transition-all duration-300 ${showHistory ? "xl:mr-96" : ""}`}
        >
          <div className="max-w-6xl w-full mx-auto px-4 py-6 flex-1 flex flex-col">
            {/* Header — left-aligned, compact */}
            <div className="mb-6">
              <div className="flex items-center gap-2 mb-1">
                <Shield className="w-5 h-5 text-primary" />
                <h1 className="text-lg font-semibold text-foreground">
                  ThreatRadar
                </h1>
              </div>
              <p className="text-xs text-muted">
                Threat intelligence aggregation — VirusTotal, AbuseIPDB, URLScan, URLHaus
              </p>
            </div>

            {/* Search — full-width, no decoration */}
            <div className="mb-6">
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
                  <Input
                    type="text"
                    placeholder="Enter URL or IP address (e.g., example.com or 8.8.8.8)"
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleScan()}
                    className="pl-9 bg-card border-border text-foreground placeholder:text-muted h-10 rounded-md text-sm font-mono-data"
                    disabled={isScanning}
                  />
                </div>
                <Button
                  onClick={() => handleScan()}
                  disabled={isScanning || !searchInput.trim()}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 h-10 rounded-md font-semibold text-sm"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin mr-1.5" />
                      Scanning
                    </>
                  ) : (
                    "Scan"
                  )}
                </Button>
                <Button
                  onClick={() => setShowHistory(!showHistory)}
                  variant="outline"
                  className="border-border text-muted-foreground hover:text-foreground hover:bg-secondary h-10 rounded-md px-3"
                >
                  <History className="w-4 h-4" />
                </Button>
              </div>
            </div>

            {/* Loading skeleton — matches data layout */}
            {isScanning && (
              <div className="space-y-4">
                <LoadingShimmer className="h-10 rounded-md" />
                <div className="grid grid-cols-1 md:grid-cols-[40%_1fr] gap-4 p-4 border border-border rounded-md">
                  <LoadingShimmer className="aspect-video rounded-sm" />
                  <div className="space-y-3">
                    <LoadingShimmer className="h-4 w-3/4 rounded-sm" />
                    <LoadingShimmer className="h-4 w-1/2 rounded-sm" />
                    <LoadingShimmer className="h-4 w-2/3 rounded-sm" />
                    <LoadingShimmer className="h-4 w-1/3 rounded-sm" />
                  </div>
                </div>
                <LoadingShimmer className="h-48 rounded-md" />
              </div>
            )}

            {/* Results */}
            {!isScanning && results && (
              <div className="space-y-4">
                {/* Result header */}
                <div className="flex items-center justify-between p-4 bg-card border border-border rounded-md">
                  <div className="flex items-center gap-3">
                    <SafetyScoreBadge score={results.globalScore} />
                    <div>
                      <p className="font-mono-data text-sm text-foreground">{results.target}</p>
                      <p className="font-mono-data text-xs text-muted">
                        {results.type.toUpperCase()} • {getRelativeTime(results.timestamp)}
                      </p>
                    </div>
                  </div>
                  <span className="font-mono-data text-xs text-muted border border-border rounded-sm px-2 py-0.5">
                    {results.type === "url" ? "URL" : "IP"}
                  </span>
                </div>

                {/* Errors — specific, not generic */}
                {results.errors && results.errors.length > 0 && (
                  <div className="p-3 bg-warning/5 border border-warning/20 rounded-md">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="text-xs font-semibold text-warning mb-1">Partial Results</p>
                        {results.errors.map((error, idx) => (
                          <p key={idx} className="font-mono-data text-xs text-destructive">{error}</p>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Source cards — compact grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {results.virusTotal && (
                    <div className="p-4 bg-card border border-border rounded-md">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted mb-3 flex items-center gap-1.5">
                        <Shield className="w-4 h-4" />
                        VirusTotal
                      </h3>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <p className="text-[11px] text-muted">Malicious</p>
                          <p className="font-mono-data text-lg font-bold text-destructive">
                            {results.virusTotal.malicious}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] text-muted">Suspicious</p>
                          <p className="font-mono-data text-lg font-bold text-warning">
                            {results.virusTotal.suspicious}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] text-muted">Clean</p>
                          <p className="font-mono-data text-lg font-bold text-success">
                            {results.virusTotal.harmless}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] text-muted">Undetected</p>
                          <p className="font-mono-data text-lg font-bold text-muted-foreground">
                            {results.virusTotal.undetected}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {results.urlHaus && (
                    <div className="p-4 bg-card border border-border rounded-md">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted mb-3 flex items-center gap-1.5">
                        <Shield className="w-4 h-4" />
                        URLHaus
                      </h3>
                      <div className="space-y-3">
                        <div>
                          <p className="text-[11px] text-muted">Status</p>
                          <p
                            className={`font-mono-data text-sm font-bold ${results.urlHaus.query_status === "ok"
                              ? results.urlHaus.url_status === "online"
                                ? "text-destructive"
                                : "text-warning"
                              : "text-success"
                              }`}
                          >
                            {results.urlHaus.query_status === "ok"
                              ? results.urlHaus.url_status === "online"
                                ? "Active Malware"
                                : "Offline Malware"
                              : "Clean / Not Found"}
                          </p>
                        </div>
                        {results.urlHaus.query_status === "ok" && (
                          <>
                            <div>
                              <p className="text-[11px] text-muted">Threat</p>
                              <p className="font-mono-data text-sm text-foreground">
                                {results.urlHaus.threat || "Unknown"}
                              </p>
                            </div>
                            <div>
                              <p className="text-[11px] text-muted mb-1">Tags</p>
                              <div className="flex flex-wrap gap-1">
                                {results.urlHaus.tags &&
                                  results.urlHaus.tags.length > 0 ? (
                                  results.urlHaus.tags.map((tag, i) => (
                                    <span
                                      key={i}
                                      className="font-mono-data px-1.5 py-0.5 border border-border rounded-sm text-[11px] text-foreground"
                                    >
                                      {tag}
                                    </span>
                                  ))
                                ) : (
                                  <span className="text-[11px] text-muted">
                                    No tags
                                  </span>
                                )}
                              </div>
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  )}

                  {results.abuseIPDB && (
                    <div className="p-4 bg-card border border-border rounded-md">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted mb-3 flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4" />
                        AbuseIPDB
                      </h3>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <p className="text-[11px] text-muted">Abuse Score</p>
                          <p className="font-mono-data text-lg font-bold text-warning">
                            {results.abuseIPDB.abuseConfidenceScore}%
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] text-muted">Reports</p>
                          <p className="font-mono-data text-lg font-bold text-foreground">
                            {results.abuseIPDB.totalReports}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] text-muted">Country</p>
                          <p className="font-mono-data text-sm text-foreground">
                            {results.abuseIPDB.countryCode}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] text-muted">ISP</p>
                          <p className="font-mono-data text-sm text-foreground truncate">
                            {results.abuseIPDB.isp}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* URLScan result card — composite */}
                {results.urlScan && (
                  <ScanResultCard results={results} />
                )}

                {/* URLScan loading indicator */}
                {!results.urlScan && isLoadingURLScan && (
                  <div className="p-4 bg-card border border-border rounded-md">
                    <div className="flex items-center gap-2 mb-3">
                      <Loader2 className="w-4 h-4 text-primary animate-spin" />
                      <span className="text-xs font-semibold uppercase tracking-wider text-muted">
                        URLScan loading — 10-30s
                      </span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-[40%_1fr] gap-4">
                      <LoadingShimmer className="aspect-video rounded-sm" />
                      <div className="space-y-2">
                        <LoadingShimmer className="h-4 w-3/4 rounded-sm" />
                        <LoadingShimmer className="h-4 w-1/2 rounded-sm" />
                        <LoadingShimmer className="h-4 w-2/3 rounded-sm" />
                      </div>
                    </div>
                  </div>
                )}

                <ThreatDataTabs results={results} />
              </div>
            )}

            {/* Empty state — muted text only, no illustrations */}
            {!isScanning && !results && (
              <div className="py-16">
                <p className="text-sm text-muted">No recent scans</p>
              </div>
            )}

            {/* Footer */}
            <footer className="mt-auto py-8 border-t border-border flex flex-col md:flex-row items-center justify-between gap-4 text-muted">
              <div className="flex items-center gap-2 text-xs">
                <span className="uppercase tracking-widest text-[10px]">Developed by</span>
                <a
                  href="https://github.com/negoro26"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-foreground hover:text-primary font-semibold transition-colors"
                >
                  negoro26
                </a>
              </div>

              <div className="flex items-center gap-1">
                <a
                  href="https://github.com/negoro26/ThreatRadar"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-1.5 hover:bg-secondary rounded-md hover:text-primary transition-colors"
                >
                  <svg
                    role="img"
                    viewBox="0 0 24 24"
                    fill="currentColor"
                    className="w-4 h-4"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
                  </svg>
                </a>
                <a
                  href="https://negoro26.github.io"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-1.5 hover:bg-secondary rounded-md hover:text-primary transition-colors"
                >
                  <Globe className="w-4 h-4" />
                </a>
              </div>
            </footer>
          </div>
        </div>

        {/* History Sidebar Overlay for Mobile */}
        <div
          className={`fixed inset-0 bg-background/40 z-[90] transition-opacity duration-300 ${showHistory ? "opacity-100" : "opacity-0 pointer-events-none"} xl:hidden`}
          onClick={() => setShowHistory(false)}
        />

        {/* Scan History Sidebar */}
        <aside
          className={`fixed right-0 top-0 h-full w-full sm:w-80 md:w-96 bg-background border-l border-border flex flex-col z-[100] transition-transform duration-300 transform ${showHistory ? "translate-x-0" : "translate-x-full"}`}
        >
          <div className="p-4 border-b border-border flex items-center justify-between">
            <h3 className="font-semibold text-sm flex items-center gap-2 text-foreground">
              <History className="w-4 h-4" />
              Scan History
            </h3>
            <Button
              onClick={() => setShowHistory(false)}
              variant="ghost"
              size="icon"
              className="h-8 w-8 rounded-md hover:bg-secondary"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-1">
            {history.length === 0 ? (
              <p className="text-sm text-muted py-8 text-center">
                No recent scans
              </p>
            ) : (
              history.map((item, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setSearchInput(item.target);
                    handleScan(item.target);
                    setShowHistory(false);
                  }}
                  className="w-full p-3 bg-card hover:bg-secondary rounded-md border border-border text-left transition-colors focus:outline-none focus:ring-1 focus:ring-primary/30"
                >
                  <p className="font-mono-data text-sm text-foreground truncate mb-1">
                    {item.target}
                  </p>
                  <div className="flex items-center justify-between">
                    <span className="font-mono-data text-[11px] text-muted">
                      {getRelativeTime(item.timestamp)}
                    </span>
                    <SafetyScoreBadge score={item.globalScore} showLabel={false} className="text-[10px] px-1.5 py-0.5" />
                  </div>
                </button>
              ))
            )}
          </div>

          {history.length > 0 && (
            <div className="p-3 border-t border-border">
              <Button
                onClick={clearHistory}
                variant="outline"
                className="w-full border-border text-muted hover:text-destructive hover:border-destructive/30 rounded-md h-9 text-xs font-semibold uppercase tracking-wider"
              >
                Clear History
              </Button>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
