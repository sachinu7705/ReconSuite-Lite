"use strict";

const $ = (id) => document.getElementById(id);

let chatBusy = false;
let analysisBusy = false;
let lastResult = "";

async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }

  return data;
}

function addMessage(role, content) {
  const bubble = document.createElement("div");
  bubble.className = `bubble ${role}`;
  bubble.textContent = content;
  $("chatMessages").append(bubble);
  $("chatMessages").scrollTop = $("chatMessages").scrollHeight;
}

function setBusy(kind, busy) {
  if (kind === "chat") {
    chatBusy = busy;
    $("sendButton").disabled = busy;
    $("chatInput").disabled = busy;
  } else {
    analysisBusy = busy;
    document.querySelectorAll("[data-analysis]").forEach((button) => {
      button.disabled = busy;
    });
  }
}

function showResult(title, answer) {
  lastResult = answer;
  $("resultDescription").textContent = title;
  $("analysisResult").textContent = answer;
  $("copyResult").disabled = !answer;
}

async function checkAI() {
  try {
    const data = await apiRequest("/api/ai/health");
    $("serviceStatus").textContent = `Available · ${data.model}`;
    $("serviceStatus").classList.remove("error");
  } catch (error) {
    $("serviceStatus").textContent = `Unavailable · ${error.message}`;
    $("serviceStatus").classList.add("error");
  }
}

$("chatForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (chatBusy) return;

  const message = $("chatInput").value.trim();
  if (!message) return;

  addMessage("user", message);
  $("chatInput").value = "";
  setBusy("chat", true);
  addMessage("assistant", "Thinking...");

  const pending = $("chatMessages").lastElementChild;

  try {
    const data = await apiRequest("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ message, evidence: {} })
    });

    pending.textContent = data.answer;
    showResult("AI Chat response", data.answer);
  } catch (error) {
    pending.textContent = `Error: ${error.message}`;
  } finally {
    setBusy("chat", false);
    $("chatInput").focus();
  }
});

document.querySelectorAll("[data-analysis]").forEach((button) => {
  button.addEventListener("click", async () => {
    if (analysisBusy) return;

    const type = button.dataset.analysis;
    const fields = {
      vulnerability: {
        input: "assessmentId",
        endpoint: "/api/ai/analyze/vulnerability/",
        title: "Vulnerability Assessment Analysis"
      },
      "port-scan": {
        input: "scanId",
        endpoint: "/api/ai/analyze/port-scan/",
        title: "Saved Port Scan Analysis"
      },
      recon: {
        input: "reportId",
        endpoint: "/api/ai/analyze/recon/",
        title: "Recon Report Analysis"
      }
    };

    const config = fields[type];
    const id = $(config.input).value.trim();

    if (!id) {
      showResult(config.title, "Enter an existing saved record ID first.");
      return;
    }

    // Restrict IDs to a single URL path segment.
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) {
      showResult(config.title, "Invalid ID format.");
      return;
    }

    setBusy("analysis", true);
    showResult(config.title, "Analyzing existing evidence. No scan is being started...");

    try {
      const data = await apiRequest(
        config.endpoint + encodeURIComponent(id),
        { method: "POST", body: JSON.stringify({}) }
      );

      showResult(config.title, data.answer);
    } catch (error) {
      showResult(config.title, `Analysis failed: ${error.message}`);
    } finally {
      setBusy("analysis", false);
    }
  });
});

$("clearChat").addEventListener("click", () => {
  $("chatMessages").replaceChildren();
  addMessage(
    "assistant",
    "Chat cleared. Ask a new defensive security question."
  );
});

$("copyResult").addEventListener("click", async () => {
  if (!lastResult) return;

  try {
    await navigator.clipboard.writeText(lastResult);
    $("copyResult").textContent = "Copied!";
    setTimeout(() => {
      $("copyResult").textContent = "Copy Result";
    }, 1500);
  } catch {
    $("resultDescription").textContent =
      "Clipboard access failed. Select and copy the result manually.";
  }
});

checkAI();
