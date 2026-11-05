const $ = id => document.getElementById(id);

let latestResult = null;

function formatValue(value) {
  if (Array.isArray(value)) {
    return value.map(formatValue).join("\n");
  }

  if (value && typeof value === "object") {
    return Object.entries(value)
      .map(([key, item]) => `${key}: ${formatValue(item)}`)
      .join("\n");
  }

  return value === null || value === undefined
    ? "Not available"
    : String(value);
}

$("whoisForm").addEventListener("submit", async event => {
  event.preventDefault();

  const domain = $("domain").value.trim();
  const button = $("lookupBtn");

  button.disabled = true;
  button.textContent = "Looking up...";
  $("message").textContent = "Contacting WHOIS server...";
  $("details").replaceChildren();
  $("summary").classList.add("hidden");
  $("exportBtn").disabled = true;

  try {
    const response = await fetch(
      `/api/whois/lookup?domain=${encodeURIComponent(domain)}`
    );

    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error || "WHOIS lookup failed.");
    }

    latestResult = data;
    renderWhois(data);

  } catch (error) {
    latestResult = null;
    $("message").textContent = error.message;

    const message = document.createElement("p");
    message.textContent = "No WHOIS information available.";
    $("details").replaceChildren(message);

  } finally {
    button.disabled = false;
    button.textContent = "Lookup WHOIS";
  }
});

function renderWhois(data) {
  $("message").textContent =
    `WHOIS lookup completed for ${data.domain}`;

  const details = data.details || {};
  const summary = $("summary");
  summary.replaceChildren();

  const summaryItems = [
    ["Registrar", details.registrar],
    ["Created", details.creation_date],
    ["Expires", details.expiration_date]
  ];

  summaryItems.forEach(([label, value]) => {
    const card = document.createElement("div");
    card.className = "summary-card";

    const title = document.createElement("span");
    title.textContent = label;

    const content = document.createElement("strong");
    content.textContent = formatValue(value);

    card.append(title, content);
    summary.append(card);
  });

  summary.classList.remove("hidden");

  const grid = $("details");
  grid.replaceChildren();

  Object.entries(details).forEach(([key, value]) => {
    const card = document.createElement("div");
    card.className = "detail-card";

    const label = document.createElement("span");
    label.textContent = key.replaceAll("_", " ").toUpperCase();

    const content = document.createElement("strong");
    content.textContent = formatValue(value);

    card.append(label, content);
    grid.append(card);
  });

  $("exportBtn").disabled = false;
}

$("exportBtn").addEventListener("click", async () => {
  if (!latestResult) return;

  const button = $("exportBtn");
  button.disabled = true;
  button.textContent = "Generating PDF...";

  try {
    const response = await fetch(
      `/api/whois/pdf?domain=${encodeURIComponent(latestResult.domain)}`
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "PDF generation failed.");
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = `whois-${latestResult.domain}.pdf`;
    link.click();

    URL.revokeObjectURL(url);

  } catch (error) {
    $("message").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Export PDF";
  }
});

$("whoisForm").requestSubmit();
