"use server";

import { isIP } from "net";
import { promises as dns } from "dns";
import { calculateGlobalScore } from "@/lib/scoring";

export interface VirusTotalData {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
  last_analysis_stats?: any;
  reputation?: number;
}

export interface AbuseIPDBData {
  abuseConfidenceScore: number;
  countryCode: string;
  usageType: string;
  isp: string;
  domain: string;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
}

export interface URLScanData {
  screenshotUrl: string;
  technologies: Array<{
    app: string;
    confidence: number;
    confidenceTotal: number;
    icon?: string;
    website?: string;
    categories?: string[];
  }>;
  verdict: {
    malicious: boolean;
    score: number;
  };
  page: {
    domain: string;
    country: string;
    server: string;
  };
}

export interface URLHausData {
  query_status: string;
  id?: string;
  urlhaus_reference?: string;
  url?: string;
  url_status?: string;
  host?: string;
  date_added?: string;
  threat?: string;
  blacklists?: {
    spamhaus_dbl?: string;
    surbl?: string;
  };
  reporter?: string;
  larted?: string;
  tags?: string[];
}

export interface ThreatIntelligenceResult {
  success: boolean;
  target: string;
  type: "url" | "ip";
  globalScore: number;
  virusTotal?: VirusTotalData;
  abuseIPDB?: AbuseIPDBData;
  urlScan?: URLScanData;
  urlHaus?: URLHausData;
  errors?: string[];
  timestamp: number;
}

function isValidIP(str: string): boolean {
  return isIP(str) !== 0;
}

function isValidURL(str: string): boolean {
  try {
    new URL(str);
    return true;
  } catch {
    return false;
  }
}

async function resolveHostname(url: string): Promise<string | null> {
  try {
    const hostname = new URL(url).hostname;
    const lookup = await dns.lookup(hostname);
    return lookup.address;
  } catch (e) {
    console.warn(`Could not resolve hostname: ${url}`, e);
    return null;
  }
}

async function fetchVirusTotal(
  target: string,
  type: "url" | "ip",
): Promise<VirusTotalData | null> {
  try {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      console.warn("VirusTotal API key not configured");
      return null;
    }

    let endpoint: string;
    if (type === "url") {
      const urlId = Buffer.from(target).toString("base64").replace(/=/g, "");
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    } else {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${target}`;
    }

    const response = await fetch(endpoint, {
      headers: {
        "x-apikey": apiKey,
      },
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status}`);
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      timeout: stats.timeout || 0,
      last_analysis_stats: stats,
      reputation: data.data.attributes.reputation || 0,
    };
  } catch (error) {
    console.error("VirusTotal fetch error:", error);
    return null;
  }
}

async function fetchAbuseIPDB(ip: string): Promise<AbuseIPDBData | null> {
  try {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
      console.warn("AbuseIPDB API key not configured");
      return null;
    }

    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
      {
        headers: {
          Key: apiKey,
          Accept: "application/json",
        },
        cache: "no-store",
      },
    );

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status}`);
    }

    const data = await response.json();
    const ipData = data.data;

    return {
      abuseConfidenceScore: ipData.abuseConfidenceScore || 0,
      countryCode: ipData.countryCode || "Unknown",
      usageType: ipData.usageType || "Unknown",
      isp: ipData.isp || "Unknown",
      domain: ipData.domain || "Unknown",
      totalReports: ipData.totalReports || 0,
      numDistinctUsers: ipData.numDistinctUsers || 0,
      lastReportedAt: ipData.lastReportedAt || null,
    };
  } catch (error) {
    console.error("AbuseIPDB fetch error:", error);
    return null;
  }
}

async function fetchURLScan(url: string): Promise<URLScanData | null> {
  try {
    const apiKey = process.env.URLSCAN_API_KEY;
    if (!apiKey) {
      console.warn("URLScan API key not configured");
      return null;
    }

    const submitResponse = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "API-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        visibility: "unlisted",
      }),
      cache: "no-store",
    });

    if (submitResponse.status === 429) {
      console.warn("URLScan rate limit hit (429). Skipping scan.");
      return null;
    }

    if (!submitResponse.ok) {
      throw new Error(`URLScan submit error: ${submitResponse.status}`);
    }

    const submitData = await submitResponse.json();
    const resultUrl = submitData.api;

    await new Promise((resolve) => setTimeout(resolve, 10000));

    const maxRetries = 15;
    const pollInterval = 2000;

    for (let i = 0; i < maxRetries; i++) {
      const resultResponse = await fetch(resultUrl, {
        headers: {
          "API-Key": apiKey,
        },
        cache: "no-store",
      });

      if (resultResponse.ok) {
        const resultData = await resultResponse.json();
        return {
          screenshotUrl: resultData.task?.screenshotURL || "",
          technologies: resultData.meta?.processors?.wappa?.data || [],
          verdict: {
            malicious: resultData.verdicts?.overall?.malicious || false,
            score: resultData.verdicts?.overall?.score || 0,
          },
          page: {
            domain: resultData.page?.domain || "",
            country: resultData.page?.country || "",
            server: resultData.page?.server || "",
          },
        };
      }

      if (resultResponse.status === 404) {
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
        continue;
      }

      if (resultResponse.status === 410) {
        console.warn("URLScan result was deleted (410)");
        return null;
      }

      throw new Error(`URLScan result error: ${resultResponse.status}`);
    }

    throw new Error("URLScan timeout: Report took too long to generate");
  } catch (error) {
    console.error("URLScan fetch error:", error);
    return null;
  }
}

async function fetchURLHaus(url: string): Promise<URLHausData | null> {
  try {
    // URLHaus public API (https://urlhaus-api.abuse.ch/v1/url/)
    // Generally free but good to have API key support if user provides it
    const apiKey = process.env.URLHAUS_API_KEY;

    const formData = new URLSearchParams();
    formData.append("url", url);

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (apiKey) {
      headers["Auth-Key"] = apiKey;
    }

    console.log(`[URLHaus] Querying URL: ${url}`);

    const response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: headers,
      body: formData,
      cache: "no-store",
    });

    if (!response.ok) {
      // 404 from URLHaus often means "not found in database" which is good,
      // but the API usually returns 200 with query_status: "no_results"
      if (response.status === 404) {
        return null;
      }
      throw new Error(`URLHaus API error: ${response.status}`);
    }

    const data: URLHausData = await response.json();
    console.log(`[URLHaus] Response for ${url}:`, JSON.stringify(data));
    return data;
  } catch (error) {
    console.error("URLHaus fetch error:", error);
    return null;
  }
}

// calculateGlobalScore is imported from @/lib/scoring

/**
 * Fast scan: calls VirusTotal, AbuseIPDB, and URLHaus.
 * These are passive lookups and respond in ~1 second.
 * URLScan is excluded because it actively browses the URL (10-40s).
 */
export async function scanTargetFast(
  target: string,
): Promise<ThreatIntelligenceResult> {
  let cleanTarget = target.trim();

  if (
    !cleanTarget.startsWith("http://") &&
    !cleanTarget.startsWith("https://") &&
    !isValidIP(cleanTarget)
  ) {
    cleanTarget = "https://" + cleanTarget;
  }

  const type = isValidIP(cleanTarget) ? "ip" : "url";

  if (type === "url" && !isValidURL(cleanTarget)) {
    return {
      success: false,
      target: cleanTarget,
      type,
      globalScore: 0,
      errors: ["Invalid URL format"],
      timestamp: Date.now(),
    };
  }

  try {
    const resolvedIP = type === "ip" ? cleanTarget : await resolveHostname(cleanTarget);

    const results = await Promise.allSettled([
      fetchVirusTotal(
        type === "ip" && resolvedIP ? resolvedIP : cleanTarget,
        type,
      ),
      resolvedIP ? fetchAbuseIPDB(resolvedIP) : Promise.resolve(null),
      type === "url" ? fetchURLHaus(cleanTarget) : Promise.resolve(null),
    ]);

    const virusTotal =
      results[0].status === "fulfilled" ? results[0].value : null;
    const abuseIPDB =
      results[1].status === "fulfilled" ? results[1].value : null;
    const urlHaus = results[2].status === "fulfilled" ? results[2].value : null;

    const globalScore = calculateGlobalScore(virusTotal, abuseIPDB, null, urlHaus);

    const errors: string[] = [];
    if (results[0].status === "rejected") errors.push("VirusTotal failed");
    if (results[1].status === "rejected") errors.push("AbuseIPDB failed");
    if (results[2].status === "rejected") errors.push("URLHaus failed");

    return {
      success: true,
      target: cleanTarget,
      type,
      globalScore,
      virusTotal: virusTotal || undefined,
      abuseIPDB: abuseIPDB || undefined,
      urlHaus: urlHaus || undefined,
      errors: errors.length > 0 ? errors : undefined,
      timestamp: Date.now(),
    };
  } catch (error) {
    return {
      success: false,
      target: cleanTarget,
      type,
      globalScore: 0,
      errors: [error instanceof Error ? error.message : "Unknown error"],
      timestamp: Date.now(),
    };
  }
}

/**
 * Async URLScan: runs independently after the fast scan.
 * Returns URLScanData or null. The frontend can merge this
 * into the existing results and recalculate the global score.
 */
export async function scanURLScanAsync(
  target: string,
): Promise<URLScanData | null> {
  try {
    let cleanTarget = target.trim();
    if (
      !cleanTarget.startsWith("http://") &&
      !cleanTarget.startsWith("https://")
    ) {
      cleanTarget = "https://" + cleanTarget;
    }
    return await fetchURLScan(cleanTarget);
  } catch (error) {
    console.error("URLScan async error:", error);
    return null;
  }
}
