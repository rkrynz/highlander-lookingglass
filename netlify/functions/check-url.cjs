
const MAX_URL_LENGTH = 2048;
const API_TIMEOUT_MS = 8000;

function jsonResponse(statusCode, data) {
    return {
        statusCode,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
        },
        body: JSON.stringify(data)
    };
}

export const handler = async function (event) {
    // Only accept POST requests
    if (event.httpMethod !== "POST") {
        return jsonResponse(405, {
            error: "Method not allowed"
        });
    }

    // Reject oversized requests
    if ((event.body || "").length > 4096) {
        return jsonResponse(413, {
            error: "Request too large"
        });
    }

    // Validate request body
    let submittedURL;

    try {
        const body = JSON.parse(event.body || "{}");
        submittedURL = body.url;
    } catch {
        return jsonResponse(400, {
            error: "Invalid JSON request"
        });
    }

    if (
        typeof submittedURL !== "string" ||
        submittedURL.length === 0 ||
        submittedURL.length > MAX_URL_LENGTH
    ) {
        return jsonResponse(400, {
            error: "Invalid URL"
        });
    }

    let parsed;

    try {
        parsed = new URL(submittedURL);
    } catch {
        return jsonResponse(400, {
            error: "Invalid URL format"
        });
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        return jsonResponse(400, {
            error: "Only HTTP and HTTPS URLs are supported"
        });
    }

    // Avoid sending embedded credentials to Google
    if (parsed.username || parsed.password) {
        return jsonResponse(400, {
            error: "URLs containing credentials are not supported"
        });
    }

    // Reject local/private destinations
    const hostname = parsed.hostname.toLowerCase();

    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local") ||
        !hostname.includes(".")
    ) {
        return jsonResponse(400, {
            error: "Please enter a public website URL"
        });
    }

    // Read private API key from Netlify
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey) {
        return jsonResponse(503, {
            error: "Reputation service not configured"
        });
    }

    // Stop requests that take too long
    const controller = new AbortController();

    const timeout = setTimeout(function () {
        controller.abort();
    }, API_TIMEOUT_MS);

    try {
        const response = await fetch(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
                encodeURIComponent(apiKey),
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                signal: controller.signal,
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
                        threatEntries: [
                            { url: parsed.href }
                        ]
                    }
                })
            }
        );

        if (!response.ok) {
            console.error(
                "Safe Browsing API returned status:",
                response.status
            );

            return jsonResponse(502, {
                error: "Reputation service unavailable"
            });
        }

        const data = await response.json();

        return jsonResponse(200, {
            flagged:
                Array.isArray(data.matches) &&
                data.matches.length > 0
        });

    } catch (error) {
        if (error.name === "AbortError") {
            return jsonResponse(504, {
                error: "Reputation check timed out"
            });
        }

        console.error(
            "Safe Browsing request failed:",
            error.message
        );

        return jsonResponse(502, {
            error: "Reputation service unavailable"
        });

    } finally {
        clearTimeout(timeout);
    }
};

export const config = {
    path: "/.netlify/functions/check-url",
    rateLimit: {
        action: "rate_limit",
        windowLimit: 10,
        windowSize: 60,
        aggregateBy: ["ip", "domain"]
    }
};
