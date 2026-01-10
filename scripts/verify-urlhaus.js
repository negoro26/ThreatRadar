// Use native fetch available in Node 18+
async function verifyURLHaus() {
    const urlToCheck = process.argv[2] || "http://google.com";
    const apiKey = process.env.URLHAUS_API_KEY;

    console.log(`Checking URL: ${urlToCheck}`);
    console.log(`Using API Key: ${apiKey ? "Yes (Masked)" : "No (Public API)"}`);

    try {
        const formData = new URLSearchParams();
        formData.append("url", urlToCheck);

        const headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        };

        if (apiKey) {
            headers["Auth-Key"] = apiKey;
        }

        const response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
            method: "POST",
            headers: headers,
            body: formData,
        });

        if (!response.ok) {
            console.error(`Status: ${response.status}`);
            console.error(await response.text());
            return;
        }

        const data = await response.json();
        console.log("Response Data:");
        console.log(JSON.stringify(data, null, 2));

        if (data.query_status === 'ok') {
            console.log("\nVerdict: LISTED (Malicious)");
        } else if (data.query_status === 'no_results') {
            console.log("\nVerdict: NOT LISTED (Likely Safe)");
        } else {
            console.log(`\nVerdict: ${data.query_status}`);
        }

    } catch (error) {
        console.error("Error:", error);
    }
}

verifyURLHaus();
