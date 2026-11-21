
const input = document.getElementById("urlInput");
const button = document.getElementById("scanButton");
const results = document.getElementById("results");

// Check whether a hostname belongs to an official domain
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

function isOfficialDomain(hostname, domain) {
    return hostname === domain ||
           hostname.endsWith("." + domain);
}

// Scan the URL for suspicious signs
function scanURL(inputText) {
    let url;

    // Step 1: Validate URL
    
    try {
        let cleanedInput = inputText.trim();

        // Automatically add https:// if no protocol is provided
        if (!cleanedInput.includes("://")) {
            cleanedInput = "https://" + cleanedInput;
        }

        url = new URL(cleanedInput);
    } catch {

        return {
            type: "error",
            message: "Please enter a valid link starting with https://"
        };
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
        return {
            type: "error",
            message: "Please enter a website link."
        };
    }

    // Step 2: Identify the actual domain
    const hostname = url.hostname.toLowerCase();

    if (typeof tldts === "undefined") {
        return {
            type: "error",
            message:
                "The domain checker could not load.\n" +
                "Please refresh the page and try again."
        };
    }

    const parsedDomain = tldts.parse(hostname);
    const destination = parsedDomain.domain || hostname;
    const domainName = destination.split(".")[0];

    const warnings = [];

    if (url.protocol === "http:") {
        warnings.push(
            "This link uses HTTP instead of HTTPS. " +
            "Your connection may not be encrypted."
        );
    }

    // Step 3: Detect UCR impersonation
    const isUCR = isOfficialDomain(hostname, "ucr.edu");

    const ucrLookalikes = [
        "ucrr",
        "uc-r",
        "ucr-login",
        "ucrportal",
        "myucr",
        "rweb-ucr",
        "ucrsecure"
    ];

    const isLookalike = ucrLookalikes.some(function(name) {
        return domainName.includes(name);
    });

    const hasUCRName =
        hostname.includes("ucr") ||
        hostname.includes("uc-r") ||
        hostname.includes("rweb");

    if (!isUCR && (isLookalike || hasUCRName)) {
        warnings.push(
            "This website may be pretending to be UCR. " +
            "Official UCR websites use ucr.edu."
        );
    }

    // Step 4: Detect other brand impersonation
    const brands = [
        {
            name: "Amazon",
            domain: "amazon.com",
            keyword: "amazon"
        },
        {
            name: "PayPal",
            domain: "paypal.com",
            keyword: "paypal"
        },
        {
            name: "Microsoft",
            domain: "microsoft.com",
            keyword: "microsoft"
        }
    ];

    brands.forEach(function(brand) {
        const isOfficial = isOfficialDomain(
            hostname,
            brand.domain
        );
        
    const simplifiedHost = domainName
        .toLowerCase()
        .replace(/-/g, "")
        .replace(/0/g, "o")
        .replace(/1/g, "l");


        const hasBrandName =
            simplifiedHost.includes(brand.keyword);
        
        const registeredName = destination
            .split(".")[0]
            .replace(/-/g, "")
            .replace(/0/g, "o")
            .replace(/1/g, "l");

        const isCloseMatch =
            registeredName !== brand.keyword &&
            editDistance(registeredName, brand.keyword) <= 1;


        const isFakeAmazon =
            brand.name === "Amazon" &&
            simplifiedHost.includes("amazoon");

        
        if (
            !isOfficial &&
            (
                simplifiedHost === brand.keyword ||
                simplifiedHost.startsWith(brand.keyword + "login") ||
                simplifiedHost.startsWith(brand.keyword + "secure") ||
                isFakeAmazon ||
                isCloseMatch
            )
        ) {
            warnings.push(
                "This link may be pretending to be " +
                brand.name + "."
            );
        }
    });

    // Step 5: Check for other suspicious signs
    if (url.username || url.password) {
        warnings.push(
            "This link may be hiding its real destination " +
            "using an @ symbol."
        );
    }

    if (url.protocol === "http:") {
        warnings.push(
            "This website does not use HTTPS."
        );
    }

    if (hostname.includes("xn--")) {
        warnings.push(
            "This link contains unusual characters " +
            "that could disguise a website name."
        );
    }

    // Step 6: Show easy-to-understand results
    if (warnings.length > 0) {
        return {
            type: "warning",
            message:
                "⚠️ BE CAREFUL — SUSPICIOUS LINK\n\n" +
                "We found " + warnings.length +
                " warning sign(s).\n\n" +

                "WHY WE FLAGGED IT:\n" +
                warnings.map(function(warning) {
                    return "• " + warning;
                }).join("\n") +

                "\n\nWHERE THIS LINK GOES:\n" +
                destination +

                "\n\nWHAT YOU SHOULD DO:\n" +
                "• Don't open this link.\n" +
                "• Don't enter your password.\n" +
                "• Visit the official website yourself.\n" +
                "• Report suspicious UCR emails to abuse@ucr.edu."
        };
    }

    if (isUCR) {
        return {
            type: "caution",
            message:
                "🔎 OFFICIAL UCR DOMAIN\n\n" +
                "This link points to a ucr.edu website.\n\n" +

                "WEBSITE:\n" +
                hostname +

                "\n\nREMEMBER:\n" +
                "An official domain does not guarantee " +
                "that every page or link is safe."
        };
    }

    return {
        type: "caution",
        message:
            "🔎 NO OBVIOUS WARNING SIGNS\n\n" +
            "We didn't find anything suspicious " +
            "using our basic checks.\n\n" +

            "WEBSITE:\n" +
            destination +

            "\n\nREMEMBER:\n" +
            "This link has not been verified as safe.\n" +
            "Be careful with passwords and personal information."
    };
}

// Display the result
function checkLink() {
    const result = scanURL(input.value);

    results.className = result.type;
    results.textContent = result.message;
}

// Scan when button is clicked
button.addEventListener("click", checkLink);

// Scan when Enter is pressed
input.addEventListener("keydown", function(event) {
    if (event.key === "Enter") {
        checkLink();
    }
});
