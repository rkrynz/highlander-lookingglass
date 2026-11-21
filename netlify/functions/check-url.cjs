
exports.handler = async function (event) {
    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: "Method not allowed" })
        };
    }

    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: "API key not configured" })
        };
    }

    try {
        const { url } = JSON.parse(event.body || "{}");

        if (typeof url !== "string" || url.length > 2048) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: "Invalid URL" })
            };
        }

        const parsed = new URL(url);

        if (!["http:", "https:"].includes(parsed.protocol)) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: "Invalid URL protocol" })
            };
        }

        const response = await fetch(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
                encodeURIComponent(apiKey),
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    client: {
                        clientId: "highlander-lookingglass",
                        clientVersion: "1.0"
                    },
                    threatInfo: {
                        threatTypes: [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE"
                        ],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: parsed.href }]
                    }
                })
            }
        );

        if (!response.ok) {
            return {
                statusCode: 502,
                body: JSON.stringify({ error: "Reputation service unavailable" })
            };
        }

        const data = await response.json();

        return {
            statusCode: 200,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                flagged: Array.isArray(data.matches) && data.matches.length > 0
            })
        };
    } catch {
        return {
            statusCode: 400,
            body: JSON.stringify({ error: "Unable to check URL" })
        };
    }
};
