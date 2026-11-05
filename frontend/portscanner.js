
const API = "/api";
const $ = (id) => document.getElementById(id);

let activeScan = null;
let pollTimer = null;
let latestResults = [];
let latestScanId = null;
$("ports").addEventListener("change", () => {
  $("customPortsWrap").classList.toggle(
    "hidden",
    $("ports").value !== "custom"
  );
});

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }

  return data;
}

function showMessage(message) {
  $("scanStatus").textContent = message;
  $("scanLog").textContent = message;
}

function renderResults(results) {
  latestResults = results;
  const body = $("resultsBody");
  body.replaceChildren();

  if (!results.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "empty";
    cell.textContent = "No open ports reported.";
    row.append(cell);
    body.append(row);
    $("exportBtn").disabled = true;
    $("exportPdfBtn").disabled = true;
    return;
  }

  for (const result of results) {
    const row = document.createElement("tr");

    const values = [
      `${result.port}/${result.protocol}`,
      result.state,
      result.service,
      result.version || "—",
    ];

    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;

      if (index === 1) {
        cell.className = result.state === "open" ? "open" : "closed";
      }

      row.append(cell);
    });

    body.append(row);
  }

  $("exportBtn").disabled = false;
  $("exportPdfBtn").disabled = !latestScanId;
}


async function pollScan(id) {
  try {
    const data = await api(`/port-scans/${encodeURIComponent(id)}`);

    $("scanStatus").textContent =
      `${data.status.toUpperCase()} · ${data.elapsed}s · ${data.message}`;

    $("scanLog").textContent =
      `Target: ${data.target}\n` +
      `Status: ${data.status}\n` +
      `Elapsed: ${data.elapsed}s\n` +
      `Message: ${data.message}`;

    renderResults(data.results || []);

    if (["completed", "error", "stopped"].includes(data.status)) {
      clearInterval(pollTimer);
      pollTimer = null;
      activeScan = null;

      $("startBtn").disabled = false;
      $("stopBtn").disabled = true;

      if (data.status === "error") {
        showMessage(data.message);
      }

      return;
    }
  } catch (error) {
    clearInterval(pollTimer);
    pollTimer = null;
    activeScan = null;

    $("startBtn").disabled = false;
    $("stopBtn").disabled = true;

    showMessage(error.message);
  }
}


$("scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (activeScan) return;

  $("startBtn").disabled = true;
  $("stopBtn").disabled = false;
  renderResults([]);
  showMessage("Starting scan…");

  try {
    const data = await api("/port-scans", {
      method: "POST",
      body: JSON.stringify({
        target: $("target").value.trim(),
        ports: $("ports").value,
        custom_ports: $("customPorts").value,
        version_detection: $("versionDetection").checked,
      }),
    });

    activeScan = data.id;
    latestScanId = data.id;
    await pollScan(activeScan);
    if (activeScan) {
      pollTimer = setInterval(() => pollScan(activeScan), 1500);
    }
  } catch (error) {
    $("startBtn").disabled = false;
    $("stopBtn").disabled = true;
    showMessage(error.message);
  }
});

$("stopBtn").addEventListener("click", async () => {
  if (!activeScan) return;

  try {
    await api(`/port-scans/${encodeURIComponent(activeScan)}/stop`, {
      method: "POST",
      body: JSON.stringify({}),
    });

    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    activeScan = null;
    $("startBtn").disabled = false;
    $("stopBtn").disabled = true;
    showMessage("Scan stopped.");
  } catch (error) {
    showMessage(error.message);
  }
});

$("exportBtn").addEventListener("click", () => {
  if (!activeScan && latestResults.length === 0) return;
  const rows = latestResults;
  const csv = [
    ["port", "protocol", "state", "service", "version"],
    ...rows.map((r) => [
      r.port, r.protocol, r.state, r.service, r.version || "",
    ]),
  ].map((row) => row.map((v) =>
    `"${String(v).replace(/"/g, '""')}"`
  ).join(",")).join("\r\n");

  const url = URL.createObjectURL(
    new Blob([csv], { type: "text/csv;charset=utf-8" })
  );

  const link = document.createElement("a");
  link.href = url;
  link.download = "port-scan-results.csv";
  link.click();
  URL.revokeObjectURL(url);
});

api("/health")
  .then(() => {
    $("connection").textContent = "Backend connected";
    $("connection").style.color = "var(--green)";
  })
  .catch(() => {
    $("connection").textContent = "Backend unavailable";
    $("connection").style.color = "var(--red)";
  });


$("exportPdfBtn").addEventListener("click", () => {
  if (!latestScanId) {
    showMessage("Run a scan before exporting a PDF.");
    return;
  }

  window.location.href =
    `/api/port-scans/${encodeURIComponent(latestScanId)}/export.pdf`;
});  