document.getElementById("scanButton").addEventListener("click", function() {
    const url = document.getElementById("urlInput").value;

    document.getElementById("results").textContent =
        "You entered: " + url;
});
