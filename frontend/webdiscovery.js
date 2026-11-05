const scanBtn = document.getElementById("scanBtn");
const targetInput = document.getElementById("targetUrl");
const message = document.getElementById("scanMessage");
const results = document.getElementById("results");

let lastScan = null;

function setText(id, value) {
    document.getElementById(id).textContent =
        value === undefined || value === null || value === ""
            ? "Not available"
            : String(value);
}

function renderList(id, items, emptyMessage) {
    const container = document.getElementById(id);
    container.replaceChildren();

    if (!items || items.length === 0) {
        const item = document.createElement("div");
        item.className = "result-item";
        item.textContent = emptyMessage;
        container.appendChild(item);
        return;
    }

    items.forEach(value => {
        const item = document.createElement("div");
        item.className = "result-item";
        item.textContent = value;
        container.appendChild(item);
    });
}

function renderResults(data) {
    lastScan = data;
    results.classList.remove("hidden");

    const site = data.website;
    const links = data.links;

    setText("httpStatus", site.status_code + " " + site.reason);
    setText("technologyCount", data.technologies.length);
    setText("internalCount", links.internal_count);
    setText("externalCount", links.external_count);

    setText("target", data.target);
    setText("finalUrl", site.final_url);
    setText("siteTitle", site.title);
    setText("server", site.server);
    setText("contentType", site.content_type);
    setText("contentSize", site.content_length + " bytes");
    setText("description", site.description);
    setText("canonical", site.canonical);

    const securityContainer = document.getElementById("securityHeaders");
    securityContainer.replaceChildren();

    Object.entries(data.security_headers).forEach(([name, detail]) => {
        const row = document.createElement("div");
        row.className = "result-item";

        const label = document.createElement("strong");
        label.textContent = name + ": ";

        const status = document.createElement("span");
        status.className = detail.present ? "good" : "bad";
        status.textContent = detail.present ? "Present" : "Missing";

        const value = document.createElement("div");
        value.textContent = detail.value;

        row.append(label, status, value);
        securityContainer.appendChild(row);
    });

    const techContainer = document.getElementById("technologies");
    techContainer.replaceChildren();

    if (data.technologies.length === 0) {
        const tag = document.createElement("span");
        tag.className = "tag";
        tag.textContent = "No technologies detected";
        techContainer.appendChild(tag);
    } else {
        data.technologies.forEach(technology => {
            const tag = document.createElement("span");
            tag.className = "tag";
            tag.textContent = technology;
            techContainer.appendChild(tag);
        });
    }

    renderList("paths", data.discovered_paths, "No paths discovered.");
    renderList("internalLinks", links.internal, "No internal links discovered.");
    renderList("externalLinks", links.external, "No external links discovered.");
}

scanBtn.addEventListener("click", async () => {
    let url = targetInput.value.trim();

    if (!url) {
        message.textContent = "Please enter a website URL.";
        return;
    }

    if (!/^https?:\/\//i.test(url)) {
        url = "https://" + url;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";
    message.textContent = "Inspecting website. Please wait.";
    results.classList.add("hidden");

    try {
        const response = await fetch("/api/web-discovery/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok || !data.ok) {
            throw new Error(data.error || "Website scan failed.");
        }

        renderResults(data);
        message.textContent = "Scan completed successfully.";

    } catch (error) {
        message.textContent = "Error: " + error.message;
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan Website";
    }
});

document.getElementById("exportBtn").addEventListener("click", async () => {
    if (!lastScan) {
        message.textContent = "Run a scan before exporting.";
        return;
    }

    // Browser version: preserve existing print functionality.
    if (!window.reconsuite || !window.reconsuite.saveWebDiscoveryPdf) {
        window.print();
        return;
    }

    const button = document.getElementById("exportBtn");

    try {
        button.disabled = true;
        button.textContent = "Generating PDF...";

        const domain = new URL(lastScan.target).hostname;
        const date = new Date().toISOString().slice(0, 10);
        const filename = `WebDiscovery_${domain}_${date}.pdf`;

        const result = await window.reconsuite.saveWebDiscoveryPdf(filename);

        if (result.success) {
            message.textContent = "PDF saved successfully: " + result.filePath;
        } else if (result.canceled) {
            message.textContent = "PDF export cancelled.";
        } else {
            throw new Error(result.error || "PDF generation failed.");
        }

    } catch (error) {
        message.textContent = "PDF export error: " + error.message;
    } finally {
        button.disabled = false;
        button.textContent = "Export PDF";
    }
});

document.getElementById("backBtn").addEventListener("click", () => {
    window.location.href = "/";
});

targetInput.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        scanBtn.click();
    }
});
