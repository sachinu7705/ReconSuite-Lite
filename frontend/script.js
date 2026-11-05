const API = "http://127.0.0.1:8765/api";
const $ = (id) => document.getElementById(id);
const state = {connected:false, activeJob:null, rows:[], scans:[], reports:[], eventSeq:0, pollTimer:null, startedAt:null, activeTab:"subdomains", liveJobId:null};
const toolNames = {
  subfinder: "Subfinder",
  amass: "OWASP Amass",
  theHarvester: "theHarvester",
  assetfinder: "Assetfinder",
  crtsh: "crt.sh",
  chaos: "Chaos",
  sublist3r: "Sublist3r",
  shodan: "Shodan"
};
let toastTimer;

async function api(path, options={}) {
  const response = await fetch(`${API}${path}`, {headers:{"Content-Type":"application/json",...(options.headers||{})},...options});
  const data = await response.json().catch(()=>({}));
  if (!response.ok) throw new Error(data.error || `API error (${response.status})`);
  return data;
}
function toast(message) {
  $("toast").textContent = message; $("toast").classList.add("show");
  clearTimeout(toastTimer); toastTimer=setTimeout(()=>$("toast").classList.remove("show"),2800);
}
function addLog(event, rightOnly=false) {
  const row=document.createElement("div"); row.className="event-line";
  const time=document.createElement("span"); time.className="event-time"; time.textContent=`[${(event.time||new Date().toLocaleTimeString()).split("T").pop().slice(0,8)}] `;
  const level=document.createElement("span"); level.className="event-level"; level.textContent=`[${event.level||"INFO"}] `;
  const msg=document.createElement("span"); msg.textContent=event.message||"";
  row.append(time,level,msg);
  if (!rightOnly) $("activityLog").append(row.cloneNode(true));
  $("rightLog").append(row);
  while ($("rightLog").children.length>180) $("rightLog").firstChild.remove();
  while ($("activityLog").children.length>700) $("activityLog").firstChild.remove();
  $("rightLog").scrollTop=$("rightLog").scrollHeight; $("activityLog").scrollTop=$("activityLog").scrollHeight;
}
function setStatus(text, level="ready") {
  $("statusText").textContent=text; $("rightStatus").textContent=text;
  $("statusDot").style.background=level==="error"?"var(--red)":level==="running"?"var(--yellow)":"var(--green)";
}
function setProgress(pct) {
  pct=Math.max(0,Math.min(100,pct));
  $("globalProgress").style.width=`${pct}%`; $("bigProgress").style.width=`${pct}%`;
  $("progressPct").textContent=`${Math.round(pct)}%`;
}



function setToolState(toolId, status, pct) {
  const label = $(`state-${toolId}`) || $(`extra-state-${toolId}`);
  const bar = $(`bar-${toolId}`) || $(`extra-bar-${toolId}`);
  const card = document.querySelector(`[data-tool-card="${toolId}"]`);
  if (label) {
    label.textContent = status;
    label.style.color = status === "Completed" ? "var(--green)" :
      status === "Running" ? "var(--cyan)" :
      status === "Failed" ? "var(--red)" : "var(--muted)";
  }
  if (bar) bar.style.width = `${pct}%`;
  if (card) {
    card.classList.toggle("is-running", status === "Running");
    card.classList.toggle("is-completed", status === "Completed");
    card.classList.toggle("is-failed", status === "Failed");
  }
}

function selectedTools() {return [...document.querySelectorAll('.tool-options input[type="checkbox"]:checked')].map(x=>x.value);}
function renderRows() {
  const q=$("searchInput").value.trim().toLowerCase(), source=$("sourceFilter").value, status=$("statusFilter").value;
  const body=$("resultsBody"); body.replaceChildren();
  const rows=state.rows.filter(r=>(!q||`${r.subdomain} ${r.source}`.toLowerCase().includes(q)) &&
    (source==="all"||String(r.source).toLowerCase().includes(source.toLowerCase())) &&
    (status==="all"||(status==="Live"?String(r.status).toLowerCase()==="live":String(r.status).toLowerCase()!=="live")));
  
    const resultCount = $("resultCount");
  if (resultCount) resultCount.textContent = state.rows.length;

  const liveCount = $("liveCount");
  if (liveCount) liveCount.textContent = state.rows.filter(
    r => String(r.status).toLowerCase() === "live"
  ).length;

  if(!rows.length){const tr=document.createElement("tr"),td=document.createElement("td");td.colSpan=7;td.className="empty-row";td.textContent=state.rows.length?"No results match these filters.":"Run a passive scan to see results here.";tr.append(td);body.append(tr);return;}
  rows.forEach((r,i)=>{
    const tr=document.createElement("tr");
    const vals=[i+1,r.subdomain,r.source];
    vals.forEach((v,j)=>{const td=document.createElement("td");td.textContent=v??"";tr.append(td);});
    const st=document.createElement("td"),pill=document.createElement("span"),dot=document.createElement("i");
    pill.className="status-pill"+(String(r.status).toLowerCase()==="live"?" live":"");pill.append(dot,document.createTextNode(r.status||"Unknown"));st.append(pill);tr.append(st);
    const ip=document.createElement("td");ip.textContent=r.ip||r.ip_address||"—";tr.append(ip);
    const seen=document.createElement("td");seen.textContent=r.first_seen||r.created_at||"—";tr.append(seen);
    const actions=document.createElement("td");
    const open=document.createElement("button");open.className="row-action";open.title="Open HTTPS address";open.textContent="↗";open.addEventListener("click",()=>window.open(`https://${r.subdomain}`,"_blank","noopener"));
    const copy=document.createElement("button");copy.className="row-action";copy.title="Copy subdomain";copy.textContent="▢";copy.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(r.subdomain);toast("Subdomain copied");}catch{toast(r.subdomain);}});
    actions.append(open,copy);tr.append(actions);body.append(tr);
  });
}
function renderHistory() {
  const host=$("historyList");host.replaceChildren();
  if(!state.scans.length){const d=document.createElement("div");d.className="empty-small";d.textContent="No scans yet";host.append(d);return;}
  state.scans.slice(0,6).forEach(scan=>{
    const b=document.createElement("button");b.className="history-item";b.innerHTML="";
    const title=document.createElement("strong");title.textContent=scan.target||scan.id||"Saved scan";
    const sub=document.createElement("small");sub.textContent=`${(scan.results||[]).length} results · ${scan.status||"saved"}`;
    b.append(title,sub);b.addEventListener("click",()=>loadScan(scan.id));host.append(b);
  });
}
async function refreshHistory() {
  try{state.scans=await api("/scans");renderHistory();}catch(e){addLog({level:"WARN",message:`History refresh: ${e.message}`});}
}
async function refreshReports() {
  try{state.reports=await api("/reports");$("metricReports").textContent=state.reports.length;}catch(e){addLog({level:"WARN",message:`Report refresh: ${e.message}`});}
}
async function loadScan(id) {
  try{
    const scan=await api(`/scans/${encodeURIComponent(id)}`);state.activeJob=scan.id;state.rows=scan.results||[];
    $("targetInput").value=scan.target||"";$("metricSubs").textContent=state.rows.length;
    $("metricLive").textContent=state.rows.filter(r=>String(r.status).toLowerCase()==="live").length;
    renderRows();setStatus(`Loaded ${scan.target||id}`);toast("Saved scan loaded");
    if(scan.report) state.latestReport=scan.report;
  }catch(e){toast(e.message);}
}
async function startScan() {
  const target=$("targetInput").value.trim(),tools=selectedTools();
  if(!target){toast("Enter a domain you are authorized to assess.");$("targetInput").focus();return;}
  if(!tools.length){toast("Select at least one recon tool.");return;}
  $("runBtn").disabled=true;$("stopBtn").disabled=false;state.startedAt=Date.now();state.activeJob=null;state.rows=[];
  renderRows();setProgress(3);setStatus("Starting passive discovery","running");
  $("currentTool").textContent="Preparing";$("targetHint").textContent=target;
  $("progressTools").textContent=`0 / ${tools.length}`;$("metricTools").textContent=`0 / ${tools.length}`;
  tools.forEach(t=>setToolState(t,"Queued",0));
  addLog({level:"INFO",message:`Starting passive recon for ${target}`});
  try{
    const job=await api("/scans",{method:"POST",body:JSON.stringify({target,tools})});
    state.activeJob=job.id;state.liveJobId=job.id;
    addLog({level:"SUCCESS",message:`Job ${job.id} queued for ${job.target}`});
    pollJob();
  }catch(e){
    $("runBtn").disabled=false;$("stopBtn").disabled=true;setStatus("Unable to start scan","error");setProgress(0);toast(e.message);addLog({level:"ERROR",message:e.message});
  }
}
async function pollJob() {
  if (!state.activeJob) return;
  try {
    const job = await api(`/scans/${encodeURIComponent(state.activeJob)}`);
    if (Array.isArray(job.results)) {
      state.rows = job.results; renderRows();
      $("metricSubs").textContent = state.rows.length;
      $("metricLive").textContent = state.rows.filter(r => String(r.status).toLowerCase() === "live").length;
    }

    const tools = Array.isArray(job.tools) ? job.tools : selectedTools();
    const toolStatus = {...(job.tool_status || {})};

    // Fallback: interpret real engine events retained in the job output.
    // This keeps the UI responsive if an older backend instance omitted tool_status.
    (job.output || []).forEach(line => {
      const start = String(line).match(/^\[TOOL_START\]\s+(.+)$/);
      const done = String(line).match(/^\[TOOL_DONE\]\s+(\S+)\s+(completed|failed)$/i);
      const key = value => ({theharvester: "theHarvester"}[String(value).toLowerCase()] || String(value).toLowerCase());
      if (start) { const id = key(start[1].trim()); if (tools.some(t => key(t) === id)) toolStatus[tools.find(t => key(t) === id)] = "running"; }
      if (done) { const id = key(done[1]); const match = tools.find(t => key(t) === id); if (match) toolStatus[match] = done[2].toLowerCase(); }
    });

    const status = String(job.status || "running").toLowerCase();
    $("currentTool").textContent = job.current_tool || "—";
    const elapsed = state.startedAt ? Math.floor((Date.now() - state.startedAt) / 1000) : 0;
    $("elapsedTime").textContent = `${String(Math.floor(elapsed / 60)).padStart(2,"0")}:${String(elapsed % 60).padStart(2,"0")}`;
    setStatus(status === "completed" ? "Scan completed" : status === "error" ? "Scan failed" : status === "stopping" ? "Stopping…" : "Enumerating…", status === "error" ? "error" : status === "completed" ? "ready" : "running");

    const finished = tools.filter(t => ["completed", "failed"].includes(String(toolStatus[t] || "").toLowerCase())).length;
    $("progressTools").textContent = `${finished} / ${tools.length}`;
    $("metricTools").textContent = `${finished} / ${tools.length}`;
    setProgress(tools.length ? (finished / tools.length) * 100 : 0);

    tools.forEach(id => {
      const value = String(toolStatus[id] || "queued").toLowerCase();
      setToolState(id, value === "completed" ? "Completed" : value === "failed" ? "Failed" : value === "running" ? "Running" : "Queued", value === "completed" || value === "failed" ? 100 : value === "running" ? 55 : 0);
    });

    if (["completed", "error", "stopped"].includes(status)) {
      $("runBtn").disabled = false; $("stopBtn").disabled = true;
      $("targetHint").textContent = `Job ${job.id}`;
      if (job.error) addLog({level:"ERROR", message:job.error});
      await refreshHistory(); await refreshReports();
      toast(status === "completed" ? "Recon completed" : "Recon finished with errors");
      state.activeJob = null;
      return;
    }
  } catch (e) { addLog({level:"WARN", message:`Status poll: ${e.message}`}); }
  setTimeout(pollJob, 1000);
}

async function stopScan() {
  if(!state.activeJob)return;
  try{await api(`/scans/${encodeURIComponent(state.activeJob)}/stop`,{method:"POST",body:"{}"});setStatus("Stop requested","running");addLog({level:"WARN",message:"Stop requested by user"});}catch(e){toast(e.message);}
}
function getFilteredRows() {
  const q=$("searchInput").value.trim().toLowerCase();
  const source=$("sourceFilter").value;
  const status=$("statusFilter").value;
  return state.rows.filter(r=>(!q||`${r.subdomain} ${r.source||""}`.toLowerCase().includes(q)) &&
    (source==="all"||String(r.source||"").toLowerCase().includes(source.toLowerCase())) &&
    (status==="all"||(status==="Live"?String(r.status).toLowerCase()==="live":String(r.status).toLowerCase()!=="live")));
}
async function exportPdf() {
  const rows=getFilteredRows();
  if(!rows.length){toast("No results to export yet.");return;}
  try {
    const response=await fetch(`${API}/export/pdf`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({rows, target:$('targetInput').value.trim()})});
    if(!response.ok){const problem=await response.json().catch(()=>({}));throw new Error(problem.error||`PDF export failed (${response.status})`);}
    const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement("a");
    a.href=url;a.download="reconsuite-subdomains-status.pdf";a.click();URL.revokeObjectURL(url);toast(`Exported ${rows.length} rows to PDF`);
  } catch(e){toast(e.message);}
}
async function pollEvents() {
  try{
    const result=await api(`/events?after=${state.eventSeq}`);
    for(const event of result.events||[]){addLog(event);state.eventSeq=Math.max(state.eventSeq,event.seq||0);}
  }catch(e){/* health status is handled separately */}
  setTimeout(pollEvents,1000);
}

async function checkHealth() {
  const apiState = $("apiState");

  try {
    const result = await api("/health");
    state.connected = true;

    if (apiState) {
      apiState.classList.add("connected");
      apiState.innerHTML = "<i></i> Backend connected";
    }

    if (!result.engine_found) {
      addLog({
        level: "WARN",
        message: "Recon engine missing: put unified_subdomain_recon.py in backend/"
      });
    }

    await refreshHistory();
    await refreshReports();

  } catch (error) {
    state.connected = false;

    if (apiState) {
      apiState.classList.remove("connected");
      apiState.innerHTML = "<i></i> Backend offline";
    }

    // These dashboard elements may also be absent on other pages.
    if ($("statusText") && $("rightStatus") && $("statusDot")) {
      setStatus("Start the Python backend", "error");
    }

    if ($("rightLog") && $("activityLog")) {
      addLog({
        level: "ERROR",
        message: "Cannot connect to local API at 127.0.0.1:8765. Start backend/app.py."
      });
    } else {
      console.error(
        "Cannot connect to local API at 127.0.0.1:8765.",
        error
      );
    }
  }
}

function openReportsFolder() {
  // Renderer intentionally has no arbitrary filesystem access; show the configured local folder path.
  toast("Reports folder: recon-reports/ beside the project. Open it from your file manager.");
}
async function openReports() {
  try{
    const reports=await api("/reports");state.reports=reports;$("metricReports").textContent=reports.length;
    if(!reports.length){toast("No reports yet. Run a scan first.");return;}
    const latest=reports.find(r=>r.exists);
    if(!latest){toast("No HTML reports found; check recon engine output.");return;}
    window.open(`${API}/reports/${encodeURIComponent(latest.id)}/open`,"_blank","noopener");
  }catch(e){toast(e.message);}
}
function selectTab(tab) {
  state.activeTab=tab;document.querySelectorAll(".tab").forEach(b=>b.classList.toggle("active",b.dataset.tab===tab));
  $("resultsPanel").classList.toggle("hidden",tab==="activity"||tab==="dns");
  $("activityPanel").classList.toggle("hidden",tab!=="activity");
  $("dnsPanel").classList.toggle("hidden",tab!=="dns");
  if(tab==="live"){$("statusFilter").value="Live";renderRows();}
  else if(tab==="subdomains"){$("statusFilter").value="all";renderRows();}
}
function setup() {
  $("runBtn").addEventListener("click",startScan);$("stopBtn").addEventListener("click",stopScan);
  $("exportPdfBtn").addEventListener("click",exportPdf);$("searchInput").addEventListener("input",renderRows);
  $("sourceFilter").addEventListener("change",renderRows);$("statusFilter").addEventListener("change",renderRows);
  document.getElementById("openHistoryNavBtn")?.addEventListener("click", () => {
    window.location.href = "/history";
  });

  document.getElementById("openAIHeaderBtn")?.addEventListener("click", () => {
    window.location.href = "/ai";
  });
  $("refreshReportsBtn").addEventListener("click", refreshReports);
  $("refreshHistoryBtn").addEventListener("click",refreshHistory);$("clearLogBtn").addEventListener("click",()=>{$("rightLog").replaceChildren();});
  $("clearActivityBtn").addEventListener("click",()=>{$("activityLog").replaceChildren();});
  $("openFolderBtn").addEventListener("click",openReportsFolder);
  document.querySelectorAll(".tab").forEach(b=>b.addEventListener("click",()=>selectTab(b.dataset.tab)));
  document.querySelectorAll(".nav-item").forEach(b => {
    b.addEventListener("click", () => {
      const view = b.dataset.view;

      if (view === "web") {
        window.location.href = "/webdiscovery";
        return;
      }

      if (view === "ports") {
        window.location.href = "/portscanner";
        return;
      }
      if (view === "ai") {
        window.location.href = "/ai";
        return;
      }
      if (view === "vuln") {
        window.location.href = "/vulnerability";
        return;
      }
      if (view === "vulnerability") {
        window.location.href = "/vulnerability";
        return;
      }
      if (view === "dns") {
        window.location.href = "/dns";
        return;
      }

      if (view === "whois") {
        window.location.href = "/whois";
        return;
}
      document.querySelectorAll(".nav-item").forEach(n =>
        n.classList.remove("active")
      );
      b.classList.add("active");

      if (view === "reports") openReports();
      else if (view === "results") selectTab("subdomains");
     
      else if (view === "recon" || view === "overview") {
        $("targetInput").focus();
      }
      else if (view === "settings") {
        window.location.href = "/settings";
        return;
      }
      else {
        toast(`${b.textContent.trim()}: module is planned, not implemented in this version.`);
      }
    });
  });
  const themeBtn=$("themeBtn");if(themeBtn)themeBtn.addEventListener("click",()=>{document.body.classList.toggle("light-mode");themeBtn.textContent=document.body.classList.contains("light-mode")?"☾":"☀";});
  const settingsBtn=$("settingsBtn");if(settingsBtn)settingsBtn.addEventListener("click",()=>toast("Settings are local to this workspace."));
  const moreToolsBtn=$("moreToolsBtn");
  if (moreToolsBtn) {
    moreToolsBtn.addEventListener("click", () => {
      let menu = document.getElementById("moreToolsMenu");

      if (menu) {
        menu.classList.toggle("hidden");
        return;
      }
      menu = document.createElement("div");
      menu.id = "moreToolsMenu";
      menu.className = "more-tools-menu";

      const extraTools = [
        { id: "assetfinder", name: "Assetfinder", description: "Passive subdomain discovery" },
        { id: "crtsh", name: "crt.sh", description: "Certificate transparency search" }
      ];

      menu.innerHTML = extraTools.map(tool => `
        <label class="check extra-tool-option" for="extra-${tool.id}">
          <input id="extra-${tool.id}" type="checkbox" value="${tool.id}">
          <span class="extra-tool-copy"><strong>${tool.name}</strong><small>${tool.description}</small><span class="extra-tool-progress"><i id="extra-bar-${tool.id}"></i></span></span>
          <b class="extra-tool-state" id="extra-state-${tool.id}">Ready</b>
        </label>
      `).join("");

      moreToolsBtn.insertAdjacentElement("afterend", menu);
      menu.addEventListener("change", event => {
        if (event.target.matches('input[type="checkbox"]')) {
          event.target.closest(".extra-tool-option").classList.toggle("selected", event.target.checked);
        }
      });
      document.addEventListener("click", event => {
        if (!menu.contains(event.target) && event.target !== moreToolsBtn) menu.classList.add("hidden");
      });
    });
  }

  checkHealth();pollEvents();
}
document.addEventListener("DOMContentLoaded",setup);

