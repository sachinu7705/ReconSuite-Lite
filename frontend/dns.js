const API = "/api";

const $ = id => document.getElementById(id);
let latestResult = null;

$("dnsForm").addEventListener("submit", async event => {
  event.preventDefault();

  const domain = $("domain").value.trim();
  const button = $("lookupBtn");

  button.disabled = true;
  button.textContent = "Looking up...";
  $("message").textContent = "Querying DNS resolver...";
  $("results").replaceChildren();
  $("summary").classList.add("hidden");
  $("exportBtn").disabled = true;

  try {
    const response = await fetch(
      `${API}/dns/lookup?domain=${encodeURIComponent(domain)}`
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "DNS lookup failed.");
    }

    latestResult = data;
    renderResults(data);

  } catch (error) {
    $("message").textContent = error.message;
    $("results").innerHTML =
      '<tr><td colspan="4">No DNS records available.</td></tr>';
  } finally {
    button.disabled = false;
    button.textContent = "Lookup DNS";
  }
});

function renderResults(data) {
  $("message").textContent =
    `DNS lookup completed for ${data.domain}`;

  const summary = $("summary");
  summary.replaceChildren();

  [
    ["Total Records", data.total_records],
    ["Record Types", data.records.length],
    ["Query Errors", data.errors.length]
  ].forEach(([label, value]) => {
    const card = document.createElement("div");
    card.className = "summary-card";

    const title = document.createElement("span");
    title.textContent = label;

    const number = document.createElement("strong");
    number.textContent = value;

    card.append(title, number);
    summary.append(card);
  });

  summary.classList.remove("hidden");

  const tbody = $("results");
  tbody.replaceChildren();

  if (!data.records.length) {
    tbody.innerHTML =
      '<tr><td colspan="4">No DNS records found.</td></tr>';
  }

  data.records.forEach(record => {
    record.values.forEach(value => {
      const tr = document.createElement("tr");

      const type = document.createElement("td");
      type.textContent = record.type;

      const valueCell = document.createElement("td");
      valueCell.textContent =
        typeof value === "object" ? JSON.stringify(value) : String(value);

      const ttl = document.createElement("td");
      ttl.textContent = `${record.ttl}s`;

      const action = document.createElement("td");
      const copy = document.createElement("button");
      copy.className = "secondary";
      copy.textContent = "Copy";

      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(valueCell.textContent);
          copy.textContent = "Copied";
        } catch {
          copy.textContent = "Copy failed";
        }
      });

      action.append(copy);
      tr.append(type, valueCell, ttl, action);
      tbody.append(tr);
    });
  });

  $("exportBtn").disabled = !data.records.length;
}

$("exportBtn").addEventListener("click", async () => {
  if (!latestResult) return;

  const button = $("exportBtn");
  button.disabled = true;
  button.textContent = "Generating PDF...";

  try {
    const response = await fetch(
      `/api/dns/pdf?domain=${encodeURIComponent(latestResult.domain)}`
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "PDF generation failed.");
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = `dns-${latestResult.domain}.pdf`;
    link.click();

    URL.revokeObjectURL(url);

  } catch (error) {
    $("message").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Export PDF";
  }
});

$("dnsForm").requestSubmit();
