import type { VirusTotalData, AbuseIPDBData, URLScanData, URLHausData } from "@/app/actions/threat-intel";

export function calculateGlobalScore(
    virusTotal: VirusTotalData | null,
    abuseIPDB: AbuseIPDBData | null,
    urlScan: URLScanData | null,
    urlHaus: URLHausData | null,
): number {
    // Immediate return 0 if URLHaus confirms active malware
    if (urlHaus?.query_status === "ok" && urlHaus?.url_status === "online") {
        return 0;
    }

    let totalScore = 100;
    let weights = 0;

    if (virusTotal) {
        const total =
            virusTotal.malicious +
            virusTotal.suspicious +
            virusTotal.harmless +
            virusTotal.undetected;
        if (total > 0) {
            const vtScore =
                100 - (virusTotal.malicious * 100 + virusTotal.suspicious * 50) / total;
            totalScore += vtScore * 0.4;
            weights += 0.4;
        }
    }

    if (abuseIPDB) {
        const abuseScore = 100 - abuseIPDB.abuseConfidenceScore;
        totalScore += abuseScore * 0.3;
        weights += 0.3;
    }

    if (urlScan) {
        const scanScore = urlScan.verdict.malicious
            ? 0
            : 100 - urlScan.verdict.score;
        totalScore += scanScore * 0.3;
        weights += 0.3;
    }

    if (urlHaus) {
        if (urlHaus.query_status === "ok") {
            // url_status: "offline" or "unknown" (online already handled above)
            if (urlHaus.url_status === "offline") {
                totalScore += 20;
                weights += 0.3;
            } else {
                // Unknown status but listed
                totalScore += 10;
                weights += 0.4;
            }
        } else if (urlHaus.query_status === "no_results") {
            totalScore += 100 * 0.3;
            weights += 0.3;
        }
    }

    if (weights === 0) return 50;

    return Math.round(totalScore / (1 + weights));
}
