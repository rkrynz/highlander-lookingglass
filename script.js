
const input = document.getElementById("urlInput");
const button = document.getElementById("scanButton");
const results = document.getElementById("results");

function scanURL(inputText) {
    let url;

    // Step 1: Validate the URL
    try {
        url = new URL(inputText.trim());
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

    // Step 2: Find the website's hostname
    const hostname = url.hostname.toLowerCase();

    // Basic destination extraction for this prototype.
    // This does not handle every domain suffix.
    const parsedDomain = tldts.parse(hostname);
    const destination = parsedDomain.domain || hostname;


    // Step 3: Check whether the link belongs to UCR
    const isUCR =
        hostname === "ucr.edu" ||
        hostname.endsWith(".ucr.edu");

    // Step 4: Look for warning signs
    const warnings = [];

    if (hostname.includes("ucr") && !isUCR) {
        warnings.push(
            "This link may be pretending to be a UCR website."
        );
    }

    if (url.username || url.password) {
        warnings.push(
            "This link may be hiding its real destination."
        );
    }

    if (url.protocol === "http:") {
        warnings.push(
            "This link does not use HTTPS."
        );
    }

    // Step 5: Create a simple result for students
    if (warnings.length > 0) {
        return {
            type: "warning",
            message:
                "⚠️ Suspicious Link!\n\n" +
                warnings.join("\n") +
                "\n\nWebsite shown in link: " + hostname +
                "\nBasic destination: " + destination +
                "\n\nWhat should you do?\n" +
                "• Do not enter your password.\n" +
                "• Do not click the suspicious link.\n" +
                "• Visit the official website directly."
        };
    }

    if (isUCR) {
        return {
            type: "caution",
            message:
                "UCR Domain Recognized\n\n" +
                "This link uses an official UCR domain.\n" +
                "Website: " + hostname +
                "\n\nThis does not guarantee the page is safe."
        };
    }

    return {
        type: "caution",
        message:
            "No Obvious Warning Signs Found\n\n" +
            "Website: " + hostname +
            "\nBasic destination: " + destination +
            "\n\nThis link has not been verified as safe.\n" +
            "Be careful before entering personal information."
    };
}

function checkLink() {
    const result = scanURL(input.value);

    results.className = result.type;
    results.textContent = result.message;
}

button.addEventListener("click", checkLink);

input.addEventListener("keydown", function(event) {
    if (event.key === "Enter") {
        checkLink();
    }
});
