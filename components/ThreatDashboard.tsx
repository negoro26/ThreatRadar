"use client";

import { useState, useEffect } from "react";
import { Search, Shield, AlertTriangle, History, X } from "lucide-react";
import {
  scanTarget,
  ThreatIntelligenceResult,
} from "@/app/actions/threat-intel";
import { SafetyGauge } from "./SafetyGauge";
import { ScreenshotCard } from "./ScreenshotCard";
import { ThreatDataTabs } from "./ThreatDataTabs";
import { LoadingShimmer } from "./LoadingShimmer";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

interface SearchHistory extends ThreatIntelligenceResult { }

export function ThreatDashboard() {
  const [searchInput, setSearchInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ThreatIntelligenceResult | null>(null);
  const [history, setHistory] = useState<SearchHistory[]>([]);
  const [showHistory, setShowHistory] = useState(false);

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

    const cachedResult = history.find((h) => h.target === targetToScan);

    const CACHE_DURATION = 60 * 60 * 1000;

    if (cachedResult) {
      const isFresh = Date.now() - cachedResult.timestamp < CACHE_DURATION;

      if (isFresh) {
        console.log("HIT: Loading result from cache");
        setResults(cachedResult);
        return;
      } else {
        console.log("Cache expired. Calling API");
      }
    }
    setIsScanning(true);
    setResults(null);

    try {
      const result = await scanTarget(targetToScan);
      setResults(result);
      if (result.success) {
        saveToHistory(result);
      }
    } catch (error) {
      console.error("Scan error:", error);
    } finally {
      setIsScanning(false);
    }
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("threat-scan-history");
  };

  const getThreatLevel = (score: number) => {
    if (score >= 80) return { label: "Safe", color: "text-emerald-400" };
    if (score >= 60) return { label: "Low Risk", color: "text-emerald-500" };
    if (score >= 40) return { label: "Moderate", color: "text-yellow-500" };
    if (score >= 20) return { label: "High Risk", color: "text-orange-500" };
    return { label: "Critical", color: "text-rose-500" };
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="flex">
        <div
          className={`flex-1 transition-all duration-300 ${showHistory ? "mr-80" : ""}`}
        >
          <div className="container mx-auto px-4 py-8">
            <div className="mb-8">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="w-8 h-8 text-emerald-400" />
                <h1 className="text-3xl font-bold bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
                  Threat Intelligence Dashboard
                </h1>
              </div>
              <p className="text-slate-400 text-sm">
                Comprehensive vulnerability scanning and threat analysis
              </p>
            </div>

            <div className="mb-8">
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                  <Input
                    type="text"
                    placeholder="Enter URL or IP address (e.g., example.com or 8.8.8.8)"
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleScan()}
                    className="pl-10 bg-slate-900 border-slate-800 text-slate-100 placeholder:text-slate-500 focus:border-emerald-500 focus:ring-emerald-500/20 h-12"
                    disabled={isScanning}
                  />
                </div>
                <Button
                  onClick={() => handleScan()}
                  disabled={isScanning || !searchInput.trim()}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white px-6 h-12 font-medium"
                >
                  {isScanning ? "Scanning..." : "Scan"}
                </Button>
                <Button
                  onClick={() => setShowHistory(!showHistory)}
                  className="bg-cyan-600 hover:bg-cyan-700 text-white px-4 h-12"
                >
                  <History className="w-5 h-5" />
                </Button>
              </div>
            </div>

            {isScanning && (
              <div className="space-y-6">
                <LoadingShimmer className="h-64 rounded-lg" />
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <LoadingShimmer className="h-80 rounded-lg" />
                  <LoadingShimmer className="h-80 rounded-lg" />
                </div>
                <LoadingShimmer className="h-96 rounded-lg" />
              </div>
            )}

            {!isScanning && results && (
              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h2 className="text-xl font-semibold mb-1">
                        Scan Results
                      </h2>
                      <p className="text-sm text-slate-400">{results.target}</p>
                      <p className="text-xs text-slate-500 mt-1">
                        Type: {results.type.toUpperCase()} • Scanned at{" "}
                        {new Date(results.timestamp).toLocaleString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {results.type === "url" && (
                        <span className="px-3 py-1 bg-cyan-500/10 text-cyan-400 rounded-full text-xs font-medium">
                          URL
                        </span>
                      )}
                      {results.type === "ip" && (
                        <span className="px-3 py-1 bg-blue-500/10 text-blue-400 rounded-full text-xs font-medium">
                          IP
                        </span>
                      )}
                    </div>
                  </div>

                  {results.errors && results.errors.length > 0 && (
                    <div className="mb-4 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5" />
                        <div>
                          <p className="text-sm text-yellow-500 font-medium mb-1">
                            Partial Results
                          </p>
                          <p className="text-xs text-slate-400">
                            Some services encountered errors:{" "}
                            {results.errors.join(", ")}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div className="lg:col-span-1">
                      <SafetyGauge score={results.globalScore} />
                      <div className="mt-4 text-center">
                        <p className="text-sm text-slate-400 mb-1">
                          Threat Level
                        </p>
                        <p
                          className={`text-lg font-bold ${getThreatLevel(results.globalScore).color}`}
                        >
                          {getThreatLevel(results.globalScore).label}
                        </p>
                      </div>
                    </div>

                    <div className="lg:col-span-2 space-y-4">
                      {results.virusTotal && (
                        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Shield className="w-4 h-4 text-emerald-400" />
                            VirusTotal Analysis
                          </h3>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                            <div>
                              <p className="text-xs text-slate-400">
                                Malicious
                              </p>
                              <p className="text-2xl font-bold text-rose-400">
                                {results.virusTotal.malicious}
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-slate-400">
                                Suspicious
                              </p>
                              <p className="text-2xl font-bold text-yellow-400">
                                {results.virusTotal.suspicious}
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-slate-400">Clean</p>
                              <p className="text-2xl font-bold text-emerald-400">
                                {results.virusTotal.harmless}
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-slate-400">
                                Undetected
                              </p>
                              <p className="text-2xl font-bold text-slate-400">
                                {results.virusTotal.undetected}
                              </p>
                            </div>
                          </div>
                        </div>
                      )}

                      {results.urlHaus && (
                        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Shield className="w-4 h-4 text-rose-400" />
                            URLHaus Analysis
                          </h3>
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <p className="text-xs text-slate-400">Status</p>
                              <p
                                className={`text-xl font-bold ${results.urlHaus.query_status === "ok"
                                  ? results.urlHaus.url_status === "online"
                                    ? "text-rose-500"
                                    : "text-yellow-500"
                                  : "text-emerald-400"
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
                                  <p className="text-xs text-slate-400">Threat</p>
                                  <p className="text-sm font-medium text-slate-300">
                                    {results.urlHaus.threat || "Unknown"}
                                  </p>
                                </div>
                                <div className="col-span-2">
                                  <p className="text-xs text-slate-400 mb-1">Tags</p>
                                  <div className="flex flex-wrap gap-1">
                                    {results.urlHaus.tags &&
                                      results.urlHaus.tags.length > 0 ? (
                                      results.urlHaus.tags.map((tag, i) => (
                                        <span
                                          key={i}
                                          className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-300"
                                        >
                                          {tag}
                                        </span>
                                      ))
                                    ) : (
                                      <span className="text-xs text-slate-500">
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
                        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-orange-400" />
                            AbuseIPDB Report
                          </h3>
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <p className="text-xs text-slate-400">
                                Abuse Score
                              </p>
                              <p className="text-2xl font-bold text-orange-400">
                                {results.abuseIPDB.abuseConfidenceScore}%
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-slate-400">
                                Total Reports
                              </p>
                              <p className="text-2xl font-bold text-slate-300">
                                {results.abuseIPDB.totalReports}
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-slate-400">Country</p>
                              <p className="text-sm font-medium text-slate-300">
                                {results.abuseIPDB.countryCode}
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-slate-400">ISP</p>
                              <p className="text-sm font-medium text-slate-300 truncate">
                                {results.abuseIPDB.isp}
                              </p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {results.urlScan && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <ScreenshotCard results={results} />
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
                      <h3 className="text-lg font-semibold mb-4">
                        Detected Technologies
                      </h3>
                      {results.urlScan.technologies.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                          {results.urlScan.technologies.map((tech, idx) => (
                            <span
                              key={idx}
                              className="px-3 py-1 bg-slate-800 border border-slate-700 rounded-full text-xs text-slate-300"
                            >
                              {tech.app}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-slate-500 text-sm">
                          No technologies detected
                        </p>
                      )}
                      <div className="mt-6 space-y-3">
                        <div>
                          <p className="text-xs text-slate-400">Domain</p>
                          <p className="text-sm text-slate-300">
                            {results.urlScan.page.domain}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-slate-400">Server</p>
                          <p className="text-sm text-slate-300">
                            {results.urlScan.page.server || "Unknown"}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-slate-400">Country</p>
                          <p className="text-sm text-slate-300">
                            {results.urlScan.page.country || "Unknown"}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <ThreatDataTabs results={results} />
              </div>
            )}

            {!isScanning && !results && (
              <div className="text-center py-20">
                <Shield className="w-16 h-16 text-slate-700 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-slate-400 mb-2">
                  Ready to Scan
                </h3>
                <p className="text-slate-500 text-sm">
                  Enter a URL or IP address above to begin threat analysis
                </p>
              </div>
            )}
          </div>
        </div>

        {showHistory && (
          <div className="fixed right-0 top-0 h-full w-80 bg-slate-900 border-l border-slate-800 shadow-2xl overflow-hidden flex flex-col">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="font-semibold flex items-center gap-2">
                <History className="w-5 h-5 text-emerald-400" />
                Scan History
              </h3>
              <Button
                onClick={() => setShowHistory(false)}
                variant="ghost"
                size="icon"
                className="h-8 w-8"
              >
                <X className="w-4 h-4" />
              </Button>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {history.length === 0 ? (
                <p className="text-slate-500 text-sm text-center py-8">
                  No scan history yet
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
                    className="w-full p-3 bg-slate-800/50 hover:bg-slate-800 rounded-lg border border-slate-700 text-left transition-colors"
                  >
                    <p className="text-sm text-slate-300 truncate mb-1">
                      {item.target}
                    </p>
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-slate-500">
                        {new Date(item.timestamp).toLocaleDateString()}
                      </p>
                      <span
                        className={`text-xs font-medium ${getThreatLevel(item.globalScore).color}`}
                      >
                        {item.globalScore}
                      </span>
                    </div>
                  </button>
                ))
              )}
            </div>
            {history.length > 0 && (
              <div className="p-4 border-t border-slate-800">
                <Button
                  onClick={clearHistory}
                  className="w-full bg-rose-700 hover:bg-rose-800 text-white px-4 h-12"
                >
                  Clear History
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
