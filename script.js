
const input = document.getElementById("urlInput");
const button = document.getElementById("scanButton");
const results = document.getElementById("results");

let activeController = null;

// Calculate similarity between two names
function editDistance(a, b) {
    const dp = [];

    for (let i = 0; i <= a.length; i++) {
        dp[i] = [i];
    }

    for (let j = 1; j <= b.length; j++) {
        dp[0][j] = j;
    }

    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;

            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            );
        }
    }

    return dp[a.length][b.length];
}

// Check exact domain or legitimate subdomain
function isOfficialDomain(hostname, domain) {
    return hostname === domain ||
           hostname.endsWith("." + domain);
}

// Normalize lookalike characters
function normalizeName(name) {
    return name.toLowerCase()
        .replace(/-/g, "")
        .replace(/0/g, "o")
        .replace(/1/g, "l");
}

// Parse and validate a website URL
function parseURL(inputText) {
    const text = inputText.trim();

    if (!text || text.length > 2048) {
        return null;
    }

    try {
        const value = text.includes("://")
            ? text
            : "https://" + text;

        const url = new URL(value);

        if (url.protocol !== "http:" &&
            url.protocol !== "https:") {
            return null;
        }

        if (!url.hostname.includes(".") &&
            url.hostname !== "localhost") {
            return null;
        }

        return url;
    } catch {
        return null;
    }
}

// Identify impersonation patterns
function isBrandImpersonation(hostname, domain, keyword, registeredName) {
    if (isOfficialDomain(hostname, domain)) {
        return false;
    }

    const normalized = normalizeName(registeredName);
    const normalizedKeyword = normalizeName(keyword);

    // Exact brand name on another domain
    if (normalized === normalizedKeyword) {
        return true;
    }

    // Common phishing additions
    const suspiciousWords = [
        "login",
        "secure",
        "verify",
        "account",
        "support",
        "signin",
        "password"
    ];

    for (const word of suspiciousWords) {
        if (normalized === normalizedKeyword + word ||
            normalized === word + normalizedKeyword) {
            return true;
        }
    }

    // One-character brand typos
    if (normalized !== normalizedKeyword &&
        editDistance(normalized, normalizedKeyword) <= 1) {
        return true;
    }

    // Detect official-looking domains hidden in subdomains
    if (hostname.includes(domain + ".")) {
        return true;
    }

    return false;
}

// Scan for suspicious URL patterns
function scanURL(inputText) {
    const url = parseURL(inputText);

    if (!url) {
        return {
            type: "error",
            message: "Please enter a valid website URL."
        };
    }

    if (typeof tldts === "undefined") {
        return {
            type: "error",
            message: "Domain checker unavailable. Please refresh."
        };
    }

    const hostname = url.hostname.toLowerCase();
    const parsedDomain = tldts.parse(hostname);
    const destination = parsedDomain.domain || hostname;
    const domainName = destination.split(".")[0];

    const warnings = [];

    // HTTP warning
    if (url.protocol === "http:") {
        warnings.push(
            "This website uses HTTP instead of HTTPS. " +
            "Your connection may not be encrypted."
        );
    }

    // UCR impersonation
    const isUCR = isOfficialDomain(hostname, "ucr.edu");

    const ucrPatterns = [
        "ucr",
        "uc-r",
        "rweb"
    ];

    const looksLikeUCR = ucrPatterns.some(function(pattern) {
        return hostname.includes(pattern);
    });

    if (!isUCR && looksLikeUCR) {
        warnings.push(
            "This website may be impersonating UC Riverside. " +
            "Official UCR websites use ucr.edu."
        );
    }

    // Other brand impersonation
    const brands = [
        { name: "Amazon", domain: "amazon.com", keyword: "amazon" },
        { name: "PayPal", domain: "paypal.com", keyword: "paypal" },
        { name: "Microsoft", domain: "microsoft.com", keyword: "microsoft" }
    ];

    brands.forEach(function(brand) {
        if (isBrandImpersonation(
            hostname,
            brand.domain,
            brand.keyword,
            domainName
        )) {
            warnings.push(
                "This website may be impersonating " +
                brand.name + "."
            );
        }
    });

    // Hidden destination using @
    if (url.username || url.password) {
        warnings.push(
            "This URL contains login information before an @ symbol, " +
            "which can disguise the destination."
        );
    }

    // Punycode
    if (hostname.includes("xn--")) {
        warnings.push(
            "This domain contains encoded characters that " +
            "could be used to imitate another website."
        );
    }

    if (warnings.length > 0) {
        return {
            type: "warning",
            message:
                "⚠️ SUSPICIOUS LINK\n\n" +
                "Found " + warnings.length + " warning sign(s).\n\n" +
                "WHY WE FLAGGED IT:\n" +
                warnings.map(function(warning) {
                    return "• " + warning;
                }).join("\n") +
                "\n\nACTUAL DOMAIN:\n" +
                destination +
                "\n\nRECOMMENDED ACTIONS:\n" +
                "• Avoid opening this link.\n" +
                "• Never enter your password on an unverified website.\n" +
                "• Visit the official website directly.\n" +
                "• Report suspicious UCR emails to abuse@ucr.edu."
        };
    }

    if (isUCR) {
        return {
            type: "caution",
            message:
                "🔎 OFFICIAL UCR DOMAIN\n\n" +
                "This URL belongs to the ucr.edu domain.\n\n" +
                "WEBSITE:\n" +
                hostname +
                "\n\nREMEMBER:\n" +
                "An official domain does not guarantee " +
                "that every page is safe."
        };
    }

    return {
        type: "caution",
        message:
            "🔎 NO OBVIOUS WARNING SIGNS\n\n" +
            "No suspicious patterns were detected " +
            "by our basic URL checks.\n\n" +
            "DOMAIN:\n" +
            destination +
            "\n\nREMEMBER:\n" +
            "This does not guarantee the website is safe."
    };
}

// Display scan results and check Google Safe Browsing
async function checkLink() {
    if (button.disabled) {
        return;
    }

    const result = scanURL(input.value);

    results.className = result.type;
    results.textContent = result.message;

    if (result.type === "error") {
        return;
    }

    const url = parseURL(input.value);

    activeController = new AbortController();

    button.disabled = true;
    button.textContent = "Scanning...";

    results.textContent += "\n\nChecking Google's threat database...";

    try {
        const response = await fetch("/.netlify/functions/check-url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url.href }),
            signal: activeController.signal
        });

        // Show a warning when the user exceeds the scan rate limit
        if (response.status === 429) {
            results.className = "caution";
            results.textContent =
                result.message +
                "\n\n⏳ TOO MANY SCANS\n\n" +
                "You've reached the scan limit.\n" +
                "Please wait about a minute before trying again.";
            return;
        }

        if (!response.ok) {
            throw new Error("API request failed");
        }

        const data = await response.json();

        if (data.flagged) {
            results.className = "warning";
            results.textContent =
                "🚨 KNOWN DANGEROUS LINK\n\n" +
                "Google Safe Browsing identified this URL " +
                "as a known threat.\n\n" +
                "Do not visit this website or enter personal information.\n\n" +
                "LOCAL URL CHECK:\n" +
                result.message;
        } else {
            results.textContent =
                result.message +
                "\n\nGOOGLE SAFE BROWSING:\n" +
                "No known threat was found in Google's database.\n" +
                "This does not guarantee the website is safe.";
        }
    } catch (error) {
        if (error.name !== "AbortError") {
            results.textContent =
                result.message +
                "\n\nGOOGLE SAFE BROWSING:\n" +
                "Reputation check unavailable. " +
                "Only basic URL checks were completed.";
        }
    } finally {
        button.disabled = false;
        button.textContent = "Check Link";
        activeController = null;
    }
}

// Scan button
button.addEventListener("click", checkLink);

// Enter key
input.addEventListener("keydown", function(event) {
    if (event.key === "Enter") {
        checkLink();
    }
});
