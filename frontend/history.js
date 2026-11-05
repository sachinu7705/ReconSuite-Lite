
"use strict";

const $ = (id) => document.getElementById(id);

let currentModule = "recon";
let historyRecords = [];
let pendingDelete = null;

// ---------------- CUSTOM DELETE MODAL ----------------

function openDeleteModal(reportId, deleteButton, type = "recon") {
  const modal = $("deleteConfirmModal");

  if (!modal) {
    showHistoryToast("Delete confirmation modal is missing from history.html.");
    return;
  }

  pendingDelete = { reportId, deleteButton, type };

  $("deleteModalReport").textContent = reportId;

  $("confirmDeleteBtn").textContent =
    type === "ports"
      ? "Delete Scan"
      : type === "vulnerabilities"
        ? "Delete Assessment"
        : "Delete Report";

  $("confirmDeleteBtn").disabled = false;
  $("cancelDeleteBtn").disabled = false;

  modal.hidden = false;
  $("confirmDeleteBtn").focus();
}

function closeDeleteModal() {
  const modal = $("deleteConfirmModal");
  if (modal) modal.hidden = true;

  if (pendingDelete?.deleteButton) {
    pendingDelete.deleteButton.focus();
  }

  pendingDelete = null;
}


function showHistoryToast(message) {
  const toast = $("historyToast");

  if (!toast) {
    console.error(message);
    return;
  }

  toast.textContent = message;
  toast.hidden = false;

  clearTimeout(showHistoryToast.timeout);
  showHistoryToast.timeout = setTimeout(() => {
    toast.hidden = true;
  }, 4000);
}

async function confirmDeleteReport() {
  if (!pendingDelete) return;

  const { reportId, deleteButton, type = "recon" } = pendingDelete;
  const confirmButton = $("confirmDeleteBtn");
  const cancelButton = $("cancelDeleteBtn");

  confirmButton.disabled = true;
  cancelButton.disabled = true;
  confirmButton.textContent = "Deleting…";

  if (deleteButton) {
    deleteButton.disabled = true;
    deleteButton.textContent = "Deleting…";
  }

  try {
    const deleteUrl =
      type === "ports"
        ? `/api/port-scans/${encodeURIComponent(reportId)}`
        : type === "vulnerabilities"
          ? `/api/vulnerabilities/assessments/${encodeURIComponent(reportId)}`
          : `/api/reports/${encodeURIComponent(reportId)}`;

    const response = await fetch(deleteUrl, {
      method: "DELETE"
    });
    const result = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        result.error || `Server returned ${response.status}`
      );
    }

    $("deleteConfirmModal").hidden = true;
    pendingDelete = null;

    if (type === "ports") {
      await loadPortHistory();
      showHistoryToast("Port scan deleted successfully.");
    } else {
      await loadReconHistory();
      showHistoryToast("Report deleted successfully.");
    }
  } catch (error) {
    confirmButton.disabled = false;
    cancelButton.disabled = false;
    confirmButton.textContent =
      type === "ports" ? "Delete Scan" : "Delete Report";

    if (deleteButton) {
      deleteButton.disabled = false;
      deleteButton.textContent =
        type === "ports" ? "Delete Scan" : "Delete Report";
    }

    showHistoryToast(`Could not delete item: ${error.message}`);
  }
}

// ---------------- INITIALIZATION ----------------

document.addEventListener("DOMContentLoaded", () => {
  $("reconBtn").addEventListener("click", loadReconHistory);
  $("portsBtn").addEventListener("click", loadPortHistory);
  $("vulnBtn").addEventListener("click", loadVulnerabilityHistory);

  $("moreBtn").addEventListener("click", () => {
    currentModule = "more";
    historyRecords = [];

    setPanel(
      "More Modules",
      "Future security modules can be connected here."
    );

    showMessage(
      "More history modules will appear here as they are implemented."
    );
  });

  $("search").addEventListener("input", renderHistory);

  $("refreshBtn").addEventListener("click", () => {
    if (currentModule === "recon") {
      loadReconHistory();
    } else if (currentModule === "ports") {
      loadPortHistory();
    } else if (currentModule === "vulnerabilities") {
      loadVulnerabilityHistory();
    }
  });

  $("cancelDeleteBtn").addEventListener("click", closeDeleteModal);
  $("confirmDeleteBtn").addEventListener("click", confirmDeleteReport);

  $("deleteConfirmModal").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-modal-backdrop")) {
      closeDeleteModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && pendingDelete) {
      closeDeleteModal();
    }
  });

  loadReconHistory();
});

// ---------------- SHARED HELPERS ----------------

function setPanel(title, description) {
  $("panelTitle").textContent = title;
  $("reportSummary").textContent = description;

  $("historyPanel").scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
}

function showMessage(message) {
  const list = $("reportList");
  list.replaceChildren();

  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = message;

  list.append(empty);
}

function showLoading(message) {
  showMessage(message);
}

async function fetchJSON(url) {
  const response = await fetch(url);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error || `Server returned ${response.status}`
    );
  }

  return data;
}

// ---------------- RECON HISTORY ----------------

async function loadReconHistory() {
  currentModule = "recon";
  $("search").value = "";

  setPanel(
    "Recon Reports",
    "Loading your saved reconnaissance reports..."
  );

  showLoading("Loading recon reports...");

  try {
    const data = await fetchJSON("/api/reports");

    historyRecords = Array.isArray(data)
      ? data
      : data.reports || [];

    renderHistory();
  } catch (error) {
    historyRecords = [];
    showMessage(`Could not load recon reports: ${error.message}`);
    $("reportSummary").textContent = "Failed to load recon history.";
  }
}

// ---------------- PORT SCAN HISTORY ----------------

async function loadPortHistory() {
  currentModule = "ports";
  $("search").value = "";

  setPanel(
    "Port Scan History",
    "Loading your saved port scan results..."
  );

  showLoading("Loading port scan history...");

  try {
    const data = await fetchJSON("/api/port-scans/history");

    historyRecords = Array.isArray(data)
      ? data
      : data.scans || [];

    renderHistory();
  } catch (error) {
    historyRecords = [];
    showMessage(`Could not load port scan history: ${error.message}`);
    $("reportSummary").textContent =
      "Failed to load port scan history.";
  }
}

// ---------------- VULNERABILITY HISTORY ----------------

async function loadVulnerabilityHistory() {
  currentModule = "vulnerabilities";
  $("search").value = "";

  setPanel(
    "Vulnerability History",
    "Loading your saved vulnerability assessments..."
  );

  showLoading("Loading vulnerability assessments...");

  try {
    const data = await fetchJSON(
      "/api/vulnerabilities/assessments"
    );

    historyRecords = Array.isArray(data)
      ? data
      : (
          data.assessments ||
          data.results ||
          data.records ||
          []
        );

    renderHistory();
  } catch (error) {
    historyRecords = [];
    showMessage(
      `Could not load vulnerability history: ${error.message}`
    );
    $("reportSummary").textContent =
      "Failed to load vulnerability history. Check the backend API.";
  }
}

// ---------------- HISTORY ID + COPY BUTTON ----------------

function getHistoryId(record) {
  return (
    record.id ??
    record.assessment_id ??
    record.scan_id ??
    record.report_id ??
    record.uuid ??
    ""
  );
}

function addHistoryId(info, historyId) {
  if (
    historyId === undefined ||
    historyId === null ||
    String(historyId).length === 0
  ) {
    return;
  }

  const id = String(historyId);

  const idRow = document.createElement("div");
  idRow.className = "history-id-row";

  const idLabel = document.createElement("span");
  idLabel.className = "history-id-label";
  idLabel.textContent = "ID";

  const idValue = document.createElement("code");
  idValue.className = "history-id-value";
  idValue.textContent = id;
  idValue.title = id;

  const copyButton = document.createElement("button");
  copyButton.type = "button";
  copyButton.className = "history-id-copy";
  copyButton.textContent = "Copy";
  copyButton.setAttribute("aria-label", `Copy history ID ${id}`);

  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(id);
      copyButton.textContent = "Copied!";
    } catch (error) {
      const temporaryInput = document.createElement("textarea");
      temporaryInput.value = id;
      temporaryInput.style.position = "fixed";
      temporaryInput.style.opacity = "0";
      document.body.appendChild(temporaryInput);
      temporaryInput.select();

      const copied = document.execCommand("copy");
      temporaryInput.remove();

      copyButton.textContent = copied ? "Copied!" : "Copy failed";
    }

    setTimeout(() => {
      copyButton.textContent = "Copy";
    }, 1800);
  });

  idRow.append(idLabel, idValue, copyButton);
  info.append(idRow);
}

// ---------------- SHARED HISTORY RENDERER ----------------

function renderHistory() {
  const list = $("reportList");
  const query = $("search").value.trim().toLowerCase();

  list.replaceChildren();

  const filtered = historyRecords.filter((record) => {
    const searchable = [
      record.target,
      record.url,
      record.id,
      record.assessment_id,
      record.scan_id,
      record.report_id,
      record.status,
      record.created_at,
      record.timestamp,
      record.title,
      record.severity
    ]
      .filter((value) => value !== undefined && value !== null)
      .join(" ")
      .toLowerCase();

    return searchable.includes(query);
  });

  $("reportSummary").textContent =
    `${filtered.length} record(s) shown` +
    (query ? " matching your search." : ".");

  if (!filtered.length) {
    let message;

    if (historyRecords.length) {
      message = "No records match your search.";
    } else if (currentModule === "recon") {
      message = "No recon reports found. Run a recon scan first.";
    } else if (currentModule === "ports") {
      message = "No saved port scans found. Run a port scan first.";
    } else if (currentModule === "vulnerabilities") {
      message =
        "No saved vulnerability assessments found. Run a vulnerability assessment first.";
    } else {
      message = "No history records available.";
    }

    showMessage(message);
    return;
  }

  for (const record of filtered) {
    const item = document.createElement("article");
    item.className = "report";

    const icon = document.createElement("div");
    icon.className = "report-icon";

    if (currentModule === "recon") {
      icon.textContent = "⌕";
    } else if (currentModule === "ports") {
      icon.textContent = "⌘";
    } else {
      icon.textContent = "⚑";
    }

    const info = document.createElement("div");
    info.className = "report-info";

    const title = document.createElement("strong");
    title.textContent =
      record.target ||
      record.url ||
      record.title ||
      getHistoryId(record) ||
      "Saved report";

    const details = document.createElement("small");

    if (currentModule === "recon") {
      details.textContent = record.exists
        ? `Report available · ${record.id || ""}`
        : `Report file unavailable · ${record.id || ""}`;
    } else if (currentModule === "ports") {
      const timestamp = Number(record.created_at);

      const date =
        Number.isFinite(timestamp) && timestamp > 0
          ? new Date(
              timestamp < 1e12 ? timestamp * 1000 : timestamp
            ).toLocaleString()
          : record.created_at || "Date unavailable";

      const openPorts = record.open_ports ?? "—";

      details.textContent =
        `${openPorts} open ports · ` +
        `${record.status || "Unknown"} · ${date}`;
    } else {
      const dateValue = record.created_at || record.timestamp;

      const parsedDate = dateValue
        ? new Date(
            typeof dateValue === "number" && dateValue < 1e12
              ? dateValue * 1000
              : dateValue
          )
        : null;

      const date =
        parsedDate && !Number.isNaN(parsedDate.getTime())
          ? parsedDate.toLocaleString()
          : "Date unavailable";

      const findingsCount =
        record.findings_count ??
        record.total_findings ??
        record.finding_count ??
        (
          Array.isArray(record.findings)
            ? record.findings.length
            : "—"
        );

      details.textContent =
        `${findingsCount} finding(s) · ` +
        `${record.status || "Saved"} · ${date}`;
    }

    info.append(title, details);
    addHistoryId(info, getHistoryId(record));

    const actions = document.createElement("div");
    actions.className = "report-actions";

    // Recon actions.
    if (currentModule === "recon") {
      if (record.exists && record.id) {
        const openLink = document.createElement("a");
        openLink.href =
          `/api/reports/${encodeURIComponent(record.id)}/open`;
        openLink.textContent = "Open report ↗";
        openLink.target = "_blank";
        openLink.rel = "noopener";
        actions.append(openLink);
      }

      if (record.id) {
        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.className = "delete-report-btn";
        deleteButton.textContent = "Delete Report";
        deleteButton.setAttribute(
          "aria-label",
          `Delete report ${record.id}`
        );

        deleteButton.addEventListener("click", () => {
          openDeleteModal(record.id, deleteButton, "recon");
        });

        actions.append(deleteButton);
      }
    }

    // Port scan actions: PDF + Delete Scan.
    else if (currentModule === "ports") {
      const scanId = getHistoryId(record);

      if (scanId !== undefined && scanId !== null && String(scanId)) {
        const pdfLink = document.createElement("a");
        pdfLink.href =
          `/api/port-scans/${encodeURIComponent(scanId)}/export.pdf`;
        pdfLink.textContent = "Download PDF";
        actions.append(pdfLink);

        const deleteScanButton = document.createElement("button");
        deleteScanButton.type = "button";
        deleteScanButton.className = "delete-report-btn";
        deleteScanButton.textContent = "Delete Scan";
        deleteScanButton.setAttribute(
          "aria-label",
          `Delete port scan ${scanId}`
        );

        deleteScanButton.addEventListener("click", () => {
          openDeleteModal(String(scanId), deleteScanButton, "ports");
        });

        actions.append(deleteScanButton);
      }
    }

    // Vulnerability actions.
    else if (currentModule === "vulnerabilities") {
      const assessmentId = getHistoryId(record);

      if (assessmentId !== undefined && assessmentId !== null && String(assessmentId)) {
        const pdfLink = document.createElement("a");
        pdfLink.href =
          `/api/vulnerabilities/assessments/${encodeURIComponent(assessmentId)}/export.pdf`;
        pdfLink.textContent = "Download PDF";
        actions.append(pdfLink);

        const deleteAssessmentButton = document.createElement("button");

        deleteAssessmentButton.type = "button";
        deleteAssessmentButton.className = "delete-report-btn";
        deleteAssessmentButton.textContent = "Delete Assessment";

        deleteAssessmentButton.setAttribute(
          "aria-label",
          `Delete assessment ${assessmentId}`
        );

        deleteAssessmentButton.addEventListener("click", () => {
          openDeleteModal(
            String(assessmentId),
            deleteAssessmentButton,
            "vulnerabilities"
          );
        });

        actions.append(deleteAssessmentButton);
      }
    }

    item.append(icon, info);

    if (actions.childElementCount > 0) {
      item.append(actions);
    }

    list.append(item);
  }
}
