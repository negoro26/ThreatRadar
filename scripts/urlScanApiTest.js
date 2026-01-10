// debug-urlscan.js
const API_KEY = process.env.URLSCAN_API_KEY;

if (!API_KEY) {
  console.error("❌ Error: No URLSCAN_API_KEY provided.");
  console.error("Usage: URLSCAN_API_KEY=your_key node debug-urlscan.js");
  process.exit(1);
}

const TARGET_URL = "https://google.com";

async function testUrlScan() {
  console.log(`🚀 Starting manual test for: ${TARGET_URL}`);
  console.log(`🔑 Using Key: ${API_KEY.slice(0, 5)}...`);

  try {
    // 1. Submit Scan
    console.log("1️⃣  Submitting scan request...");
    const submitResp = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "API-Key": API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: TARGET_URL,
        visibility: "unlisted",
      }),
    });

    if (!submitResp.ok) {
      const errorText = await submitResp.text();
      throw new Error(`Submission Failed (${submitResp.status}): ${errorText}`);
    }

    const submitData = await submitResp.json();
    const resultUrl = submitData.api;
    console.log(`✅ Scan submitted! ID: ${submitData.uuid}`);
    console.log(`🔗 Result API URL: ${resultUrl}`);

    // 2. Poll for Results
    console.log("2️⃣  Polling for results (max 60s)...");
    let attempts = 0;
    const maxAttempts = 12; // 12 * 5s = 60s

    while (attempts < maxAttempts) {
      attempts++;
      process.stdout.write(`   Attempt ${attempts}/${maxAttempts}... `);

      // Wait 5 seconds
      await new Promise((resolve) => setTimeout(resolve, 5000));

      const resultResp = await fetch(resultUrl, {
        headers: { "API-Key": API_KEY },
      });

      if (resultResp.status === 200) {
        const data = await resultResp.json();
        console.log("\n✅ SUCCESS! Report generated.");
        console.log("------------------------------------------------");
        console.log(`📸 Screenshot: ${data.task.screenshotURL}`);
        console.log(
          `🌎 Country:    ${data.page?.country || "Unknown"}`
        );
        console.log(
          `🚫 Malicious:  ${data.verdicts?.overall?.malicious}`
        );
        console.log("------------------------------------------------");
        return;
      } else if (resultResp.status === 404) {
        console.log("⏳ Not ready yet (404)");
      } else {
        console.log(`❌ Unexpected Status: ${resultResp.status}`);
        const text = await resultResp.text();
        console.log(text);
      }
    }

    throw new Error("Timeout: Report took too long to generate");
  } catch (error) {
    console.error("\n❌ TEST FAILED:");
    console.error(error.message);
  }
}

testUrlScan();
