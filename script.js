
document.getElementById("scanButton").addEventListener("click", function() {
    const input = document.getElementById("urlInput").value.trim();
    const results = document.getElementById("results");

    try {
        const url = new URL(input);

        if (url.protocol !== "https:" && url.protocol !== "http:") {
            results.textContent = "Please enter a website link.";
            return;
        }

        
        const hostname = url.hostname.toLowerCase();

        const isUCR =
            hostname === "ucr.edu" ||
            hostname.endsWith(".ucr.edu");

        if (hostname.includes("ucr") && !isUCR) {
            results.textContent = "⚠️ Warning: This link may be pretending to be UCR!";
        } else if (isUCR) {
            results.textContent = "This link uses an official UCR domain.";
        } else {
            results.textContent = "No UCR impersonation detected.";
        }

    } catch {
        results.textContent = "Please enter a valid URL starting with https://";
    }
});
