
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

    return {
        type: warnings.length ? "warning" : "caution",
        destination,
        hostname,
        isUCR,
        warnings
    };
}

function resultElement(tag, content, className) {
    const element = document.createElement(tag);
    element.textContent = content;
    if (className) {
        element.className = className;
    }
    return element;
}

function renderResult(result, reputation) {
    results.className = "wrap result " + (reputation.flagged ? "warning" : result.type);
    results.replaceChildren();

    const isError = result.type === "error";
    const isWarning = reputation.flagged || result.type === "warning";
    let title = "No obvious warning signs.";
    let summary = "The basic URL checks found no suspicious patterns.";

    if (isError) {
        title = "Check the link and try again.";
        summary = result.message;
    } else if (reputation.flagged) {
        title = "Known dangerous link.";
        summary = "Google Safe Browsing identified this URL as a known threat.";
    } else if (isWarning) {
        title = "Be careful — suspicious link.";
        const count = result.warnings.length;
        summary = count === 1 ? "Found 1 warning sign." : "Found " + count + " warning signs.";
    } else if (result.isUCR) {
        title = "Official UCR domain.";
        summary = "This URL belongs to the ucr.edu domain.";
    }

    const heading = resultElement("div", "", "result-header");
    const symbol = resultElement("span", isError || isWarning ? "!" : "✓", "result-symbol");
    symbol.setAttribute("aria-hidden", "true");
    const headingText = resultElement("div", "");
    headingText.append(resultElement("span", "Link scan", "eyebrow"), resultElement("h2", title), resultElement("p", summary));
    heading.append(symbol, headingText);
    results.append(heading);

    if (isError) {
        return;
    }

    const destination = resultElement("div", "", "destination");
    destination.append(resultElement("strong", "Actual domain "), resultElement("code", result.destination));
    if (result.hostname !== result.destination) {
        const hostname = resultElement("p", "Hostname ");
        hostname.append(resultElement("code", result.hostname));
        destination.append(hostname);
    }

    const details = resultElement("div", "", "result-detail");
    const localChecks = resultElement("section", "", "card");
    localChecks.append(resultElement("h3", result.warnings.length ? "Why we flagged it" : "Basic URL checks"));
    if (result.warnings.length) {
        const list = resultElement("ul", "");
        for (const warning of result.warnings) {
            list.append(resultElement("li", warning));
        }
        localChecks.append(list);
    } else {
        localChecks.append(resultElement("p", "No warning signs were detected in the URL itself."));
    }

    const nextSteps = resultElement("div", "");
    const google = resultElement("section", "", "card");
    google.append(resultElement("h3", reputation.title), resultElement("p", reputation.message));
    const advice = resultElement("section", "", "card");
    advice.append(resultElement("h3", "What to do next"));
    if (isWarning) {
        advice.append(resultElement("p", "Avoid this link. Visit the official site directly and only enter your password after verifying the address. Report suspicious UCR emails to "));
        const report = resultElement("a", "abuse@ucr.edu");
        report.href = "mailto:abuse@ucr.edu";
        advice.lastChild.append(report, ".");
    } else {
        advice.append(resultElement("p", "Verify that the address is the one you intended to visit. Even an official domain or a clean result cannot guarantee a page is safe."));
    }
    nextSteps.append(google, advice);
    details.append(localChecks, nextSteps);

    const actions = resultElement("div", "", "result-actions");
    const reset = resultElement("button", "Scan another link", "button");
    reset.type = "button";
    reset.addEventListener("click", function() {
        input.value = "";
        results.replaceChildren();
        input.focus();
    });
    actions.append(reset);
    if (reputation.pending) {
        reset.disabled = true;
    }
    results.append(destination, details, actions);
}

// Display local results while the reputation check runs.
async function checkLink() {
    if (button.disabled) {
        return;
    }

    const result = scanURL(input.value);
    if (result.type === "error") {
        renderResult(result, {});
        results.scrollIntoView({ block: "nearest" });
        return;
    }

    const url = parseURL(input.value);
    activeController = new AbortController();
    button.disabled = true;
    button.textContent = "Scanning...";
    renderResult(result, {
        title: "Google Safe Browsing",
        message: "Checking Google's threat database…",
        pending: true
    });
    results.scrollIntoView({ block: "nearest" });

    try {
        const response = await fetch("/.netlify/functions/check-url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url.href }),
            signal: activeController.signal
        });

        if (response.status === 429) {
            renderResult(result, {
                title: "Too many scans",
                message: "You've reached the scan limit. Please wait about a minute before trying again."
            });
            return;
        }

        if (!response.ok) {
            throw new Error("API request failed");
        }

        const data = await response.json();
        renderResult(result, {
            title: "Google Safe Browsing",
            flagged: data.flagged,
            message: data.flagged
                ? "This URL matched a known threat."
                : "No known threat was found in Google's database."
        });
    } catch (error) {
        if (error.name !== "AbortError") {
            renderResult(result, {
                title: "Google Safe Browsing",
                message: "Reputation check unavailable. Only basic URL checks were completed."
            });
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
