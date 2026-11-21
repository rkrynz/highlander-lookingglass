
const MAX_URL_LENGTH = 2048;
const API_TIMEOUT_MS = 8000;

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status: status,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
        }
    });
}

export default async function handler(request, context) {
    // Only allow POST requests
    if (request.method !== "POST") {
        return jsonResponse({
            error: "Method not allowed"
        }, 405);
    }

    // Check request size
    const contentLength = request.headers.get("content-length");

    if (contentLength && Number(contentLength) > 4096) {
        return jsonResponse({
            error: "Request too large"
        }, 413);
    }

    // Read JSON body
    let body;

    try {
        const rawBody = await request.text();

        if (rawBody.length > 4096) {
            return jsonResponse({
                error: "Request too large"
            }, 413);
        }

        body = JSON.parse(rawBody);
    } catch {
        return jsonResponse({
            error: "Invalid JSON request"
        }, 400);
    }

    const submittedURL = body?.url;

    // Validate URL input
    if (
        typeof submittedURL !== "string" ||
        submittedURL.length === 0 ||
        submittedURL.length > MAX_URL_LENGTH
    ) {
        return jsonResponse({
            error: "Invalid URL"
        }, 400);
    }

    let parsed;

    try {
        parsed = new URL(submittedURL);
    } catch {
        return jsonResponse({
            error: "Invalid URL format"
        }, 400);
    }

    // Only allow websites
    if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
    ) {
        return jsonResponse({
            error: "Only HTTP and HTTPS URLs are supported"
        }, 400);
    }

    // Reject URLs containing credentials
    if (parsed.username || parsed.password) {
        return jsonResponse({
            error: "URLs containing credentials are not supported"
        }, 400);
    }

    const hostname = parsed.hostname.toLowerCase();

    // Reject local hostnames
    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local") ||
        !hostname.includes(".")
    ) {
        return jsonResponse({
            error: "Please enter a public website URL"
        }, 400);
    }

    // Get Google Safe Browsing API key
    const apiKey = Netlify.env.get(
        "GOOGLE_SAFE_BROWSING_API_KEY"
    );

    if (!apiKey) {
        return jsonResponse({
            error: "Reputation service not configured"
        }, 503);
    }

    // Set timeout for Google API
    const controller = new AbortController();

    const timeout = setTimeout(function() {
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
                            {
                                url: parsed.href
                            }
                        ]
                    }
                })
            }
        );

        if (!response.ok) {
            console.error(
                "Google Safe Browsing status:",
                response.status
            );

            return jsonResponse({
                error: "Reputation service unavailable"
            }, 502);
        }

        const data = await response.json();

        const flagged =
            Array.isArray(data.matches) &&
            data.matches.length > 0;

        return jsonResponse({
            flagged: flagged
        });

    } catch (error) {
        if (error.name === "AbortError") {
            return jsonResponse({
                error: "Reputation check timed out"
            }, 504);
        }

        console.error(
            "Safe Browsing error:",
            error.message
        );

        return jsonResponse({
            error: "Reputation service unavailable"
        }, 502);

    } finally {
        clearTimeout(timeout);
    }
}

// Netlify rate limiting
export const config = {
    path: "/.netlify/functions/check-url",
    rateLimit: {
        action: "rate_limit",
        windowLimit: 10,
        windowSize: 60,
        aggregateBy: ["ip"]
    }
};
