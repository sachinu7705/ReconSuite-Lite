from __future__ import annotations
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import socket
from dotenv import load_dotenv

# Packaged application uses the user's private configuration.
# Development continues loading the project-level .env file.
env_file = os.environ.get("RECONSUITE_ENV_FILE")

if env_file:
    load_dotenv(dotenv_path=env_file)
else:
    load_dotenv()
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS


try:
    from .port_scanner import port_api
    from .vulnerability import vuln_api
    from .ai_api import ai_api
    from .dns_api import dns_api
    from .web_discovery import web_api
except ImportError:
    from port_scanner import port_api
    from vulnerability import vuln_api
    from ai_api import ai_api
    from dns_api import dns_api
    from web_discovery import web_api

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "backend" / "unified_subdomain_recon.py"
REPORTS_DIR = Path(os.environ.get("RECONSUITE_REPORTS", str(ROOT / "recon-reports"))).expanduser()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)


app.register_blueprint(port_api)
app.register_blueprint(vuln_api)
app.register_blueprint(ai_api)
app.register_blueprint(dns_api)
app.register_blueprint(web_api)


CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "file://", "null"]}})


FRONTEND_DIR = ROOT / "frontend"

@app.get("/")
def frontend_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/portscanner")
def portscanner_page():
    return send_from_directory(FRONTEND_DIR, "portscanner.html")

@app.get("/dns")
def dns_page():
    return send_from_directory(FRONTEND_DIR, "dns.html")

@app.get("/dns.css")
def dns_css():
    return send_from_directory(FRONTEND_DIR, "dns.css")

@app.get("/dns.js")
def dns_js():
    return send_from_directory(FRONTEND_DIR, "dns.js")


@app.get("/whois")
def whois_page():
    return send_from_directory(FRONTEND_DIR, "whois.html")

@app.get("/whois.css")
def whois_css():
    return send_from_directory(FRONTEND_DIR, "whois.css")

@app.get("/whois.js")
def whois_js():
    return send_from_directory(FRONTEND_DIR, "whois.js")

@app.get("/portscanner.css")
def portscanner_css():
    return send_from_directory(FRONTEND_DIR, "portscanner.css")

@app.get("/portscanner.js")
def portscanner_js():
    return send_from_directory(FRONTEND_DIR, "portscanner.js")

@app.get("/style.css")
def frontend_css():
    return send_from_directory(FRONTEND_DIR, "style.css")

@app.get("/script.js")
def frontend_js():
    return send_from_directory(FRONTEND_DIR, "script.js")


@app.get("/history")
def history_page():
    return send_from_directory(FRONTEND_DIR, "history.html")


@app.get("/history.css")
def history_css():
    return send_from_directory(FRONTEND_DIR, "history.css")


@app.get("/history.js")
def history_js():
    return send_from_directory(FRONTEND_DIR, "history.js")

@app.get("/vulnerability")
def vulnerability_page():
    return send_from_directory(FRONTEND_DIR, "vulnerability.html")

@app.get("/vulnerability.css")
def vulnerability_css():
    return send_from_directory(FRONTEND_DIR, "vulnerability.css")

@app.get("/vulnerability.js")
def vulnerability_js():
    return send_from_directory(FRONTEND_DIR, "vulnerability.js")

@app.get("/ai")
def ai_page():
    return send_from_directory(FRONTEND_DIR, "ai.html")


@app.get("/ai.css")
def ai_css():
    return send_from_directory(FRONTEND_DIR, "ai.css")


@app.get("/ai.js")
def ai_js():
    return send_from_directory(FRONTEND_DIR, "ai.js")

@app.get("/webdiscovery")
def webdiscovery_page():
    return send_from_directory(FRONTEND_DIR, "webdiscovery.html")


@app.get("/webdiscovery.css")
def webdiscovery_css():
    return send_from_directory(FRONTEND_DIR, "webdiscovery.css")


@app.get("/webdiscovery.js")
def webdiscovery_js():
    return send_from_directory(FRONTEND_DIR, "webdiscovery.js")
@app.get("/settings")
def settings_page():
    return send_from_directory(FRONTEND_DIR, "settings.html")


@app.get("/settings.css")
def settings_css():
    return send_from_directory(FRONTEND_DIR, "settings.css")


@app.get("/settings.js")
def settings_js():
    return send_from_directory(FRONTEND_DIR, "settings.js")



lock = threading.Lock()
jobs: dict[str, dict] = {}
events: list[dict] = []
MAX_EVENTS = 500
ALLOWED_TOOLS = {
    "subfinder",
    "amass",
    "theHarvester",
    "assetfinder",
    "crtsh",
}
def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def log_event(message, level="INFO", job_id=None):
    item = {"time": now(), "level": level, "message": str(message), "job_id": job_id}
    with lock:
        events.append(item)
        del events[:-MAX_EVENTS]
    return item

def normalize_input(value):
    value = str(value or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("Enter a valid domain or URL.")
    if any(c.isspace() for c in value):
        raise ValueError("Target cannot contain spaces.")
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Only http/https URLs or bare domains are accepted.")
        host = parsed.hostname
    else:
        host = value.split("/", 1)[0].split(":", 1)[0]
    host = host.lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if host.startswith("www."):
        host = host[4:]
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
        raise ValueError("Enter a valid domain, e.g. example.com.")
    return host

def load_result_rows(folder: Path):
    path = folder / "results.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("subdomains", data.get("results", data.get("hosts", [])))
    else:
        rows = []
    out = []
    for item in rows:
        if isinstance(item, str):
            out.append({"subdomain": item, "source": "Merged", "status": "Unknown"})
        elif isinstance(item, dict):
            host = item.get("subdomain") or item.get("domain") or item.get("host") or item.get("name")
            if not host:
                continue
            source = item.get("sources") or item.get("source") or "Merged"
            if isinstance(source, list):
                source = ", ".join(map(str, source))
            out.append({"subdomain": str(host), "source": str(source), "status": str(item.get("status", "Unknown"))})
    return out

def scan_worker(job_id, domain, selected_tools):
    job = jobs[job_id]
    folder = None
    try:
        if not ENGINE.exists():
            raise RuntimeError(
                "Recon engine not found. Place unified_subdomain_recon.py in backend/ "
                "or update ENGINE in backend/app.py."
            )
        outdir = REPORTS_DIR
        mapping = {
            "subfinder": "subfinder",
            "amass": "amass",
            "theHarvester": "theHarvester",
            "assetfinder": "assetfinder",
            "crtsh": "crtsh",
        }
        command = [
            sys.executable, str(ENGINE), domain, "--output", str(outdir),
            "--tools", ",".join(mapping[t] for t in selected_tools)
        ]
        job.update(status="running", current_tool="Starting", started_at=now(), command=command)
        log_event(f"Starting passive recon for {domain}", job_id=job_id)
        log_event("Tools: " + ", ".join(selected_tools), job_id=job_id)
        # Shell is deliberately disabled; only fixed executable arguments are passed.
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, cwd=str(ROOT))

        job["process"] = proc

        tool_labels = {
            "subfinder": "Subfinder",
            "amass": "OWASP Amass",
            "theharvester": "theHarvester",
            "assetfinder": "Assetfinder",
            "crtsh": "crt.sh",
        }
        job["tool_status"] = {
            tool: "queued" for tool in selected_tools
        }
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue

            job["output"].append(line)
            job["output"] = job["output"][-300:]

            low = line.lower()

            # Match engine events to the original selected-tool IDs.
            selected_tool_map = {
                tool.lower(): tool for tool in selected_tools
            }

            # A tool has actually started execution.
            if line.startswith("[TOOL_START] "):
                source_key = line.split(maxsplit=1)[1].strip().lower()
                selected_tool = selected_tool_map.get(source_key)

                if selected_tool and source_key in tool_labels:
                    job["tool_status"][selected_tool] = "running"
                    job["current_tool"] = tool_labels[source_key]

            # A tool has actually finished execution.
            elif line.startswith("[TOOL_DONE] "):
                parts = line.split()
                if len(parts) >= 3:
                    source_key = parts[1].strip().lower()
                    final_state = parts[2].strip().lower()
                    selected_tool = selected_tool_map.get(source_key)

                    if selected_tool and final_state in ("completed", "failed"):
                        job["tool_status"][selected_tool] = final_state
                        job["current_tool"] = tool_labels.get(
                            source_key, selected_tool
                        )

            # Keep compatibility with the engine's existing completion messages.
            elif line.startswith("[*] ") and ":" in line:
                message = line[4:]
                source_key = message.split(":", 1)[0].strip().lower()
                selected_tool = selected_tool_map.get(source_key)

                if selected_tool and source_key in tool_labels:
                    job["current_tool"] = tool_labels[source_key]
                    if ";" in message:
                        result_text = message.split(":", 1)[1].lower()
                        job["tool_status"][selected_tool] = (
                            "completed" if "completed" in result_text else "failed"
                        )


            log_event(
                line,
                "ERROR" if (
                    "error" in low
                    or "failed" in low
                    or "timed out" in low
                ) else "INFO",
                job_id
            )


        code = proc.wait()
        folders = [p for p in outdir.iterdir() if p.is_dir()]
        folder = max(folders, key=lambda p: p.stat().st_mtime) if folders else None
        job.update(status="completed" if code == 0 else "error",
                   exit_code=code, finished_at=now(), current_tool="Complete" if code == 0 else "Stopped / error",
                   report=str(folder / "report.html") if folder and (folder / "report.html").exists() else None,
                   results_folder=str(folder) if folder else None,
                   results=load_result_rows(folder) if folder else [])
        log_event(f"Recon process exited with code {code}; {len(job['results'])} result rows loaded.",
                  "SUCCESS" if code == 0 else "ERROR", job_id)
    except Exception as exc:
        job.update(status="error", error=str(exc), finished_at=now())
        log_event(str(exc), "ERROR", job_id)

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "engine_found": ENGINE.exists(), "reports_dir": str(REPORTS_DIR)})

@app.get("/api/tools")
def tools():
    tool_list = [
        {
            "id": "subfinder",
            "name": "Subfinder",
            "installed": shutil.which("subfinder") is not None,
        },
        {
            "id": "amass",
            "name": "OWASP Amass",
            "installed": shutil.which("amass") is not None,
        },
        {
            "id": "theHarvester",
            "name": "theHarvester",
            "installed": shutil.which("theHarvester") is not None,
        },
        {
            "id": "assetfinder",
            "name": "Assetfinder",
            "installed": shutil.which("assetfinder") is not None,
        },
        {
            "id": "crtsh",
            "name": "crt.sh",
            "installed": True,
            "type": "passive_api",
        },
        {
            "id": "chaos",
            "name": "ProjectDiscovery Chaos",
            "installed": (
                shutil.which("chaos") is not None
                and bool(os.getenv("PDCP_API_KEY"))
            ),
        },
        {
            "id": "sublist3r",
            "name": "Sublist3r",
            "installed": shutil.which("sublist3r") is not None,
        },
        {
            "id": "shodan",
            "name": "Shodan",
            "installed": bool(os.getenv("SHODAN_API_KEY")),
            "type": "api",
        },
    ]

    return jsonify(tool_list)


@app.post("/api/scans")
def start_scan():
    data = request.get_json(silent=True) or {}

    # Validate the target domain.
    try:
        domain = normalize_input(data.get("target", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    selected = data.get(
        "tools",
        ["subfinder", "amass", "theHarvester", "assetfinder"],
    )

    if not isinstance(selected, list):
        return jsonify({"error": "tools must be a list"}), 400

    # Only allow tool IDs supported by the current recon engine.
    selected = list(dict.fromkeys(
        tool for tool in selected
        if isinstance(tool, str) and tool in ALLOWED_TOOLS
    ))

    if not selected:
        return jsonify({
            "error": "Select at least one supported reconnaissance tool."
        }), 400

    # Map frontend IDs to actual installed executable names.
    EXECUTABLES = {
        "subfinder": "subfinder",
        "amass": "amass",
        "theHarvester": "theHarvester",
        "assetfinder": "assetfinder",
    }

    missing = [
        EXECUTABLES[tool]
        for tool in selected
        if tool in EXECUTABLES
        and shutil.which(EXECUTABLES[tool]) is None
    ]

    if missing:
        return jsonify({
            "error": "Missing tool(s): " + ", ".join(missing)
        }), 400

    job_id = uuid.uuid4().hex[:12]

    jobs[job_id] = {
        "id": job_id,
        "target": domain,
        "tools": selected,
        "status": "queued",
        "current_tool": "Queued",
        "started_at": now(),
        "results": [],
        "output": [],
    }

    log_event(
        "Tools selected: " + ", ".join(selected),
        job_id=job_id,
    )

    threading.Thread(
        target=scan_worker,
        args=(job_id, domain, selected),
        daemon=True,
    ).start()

    return jsonify({
        "id": job_id,
        "status": "queued",
        "target": domain,
        "tools": selected,
    }), 202


@app.get("/api/scans")
def list_scans():
    output = []

    # Include scans created during this application session.
    for job in sorted(
        jobs.values(),
        key=lambda item: item.get("started_at", ""),
        reverse=True,
    ):
        output.append({
            key: value
            for key, value in job.items()
            if key not in ("process", "command", "output")
        })

    # Include saved report folders from previous sessions.
    known = {
        job.get("results_folder")
        for job in output
        if job.get("results_folder")
    }

    if REPORTS_DIR.exists():
        folders = sorted(
            (
                path for path in REPORTS_DIR.iterdir()
                if path.is_dir()
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        for folder in folders:
            if str(folder) in known:
                continue

            rows = load_result_rows(folder)

            output.append({
                "id": folder.name,
                "target": folder.name.split("-")[0],
                "status": "saved",
                "current_tool": "Saved report",
                "results_folder": str(folder),
                "report": (
                    str(folder / "report.html")
                    if (folder / "report.html").exists()
                    else None
                ),
                "results": rows,
                "started_at": datetime.fromtimestamp(
                    folder.stat().st_mtime
                ).astimezone().isoformat(timespec="seconds"),
            })

    return jsonify(output[:100])

@app.get("/api/scans/<job_id>")
def get_scan(job_id):
    job = jobs.get(job_id)
    if job:
        return jsonify({k: v for k, v in job.items() if k not in ("process", "command")})
    # Search saved scan folders by name.
    folder = REPORTS_DIR / job_id
    if folder.is_dir():
        return jsonify({"id": job_id, "target": job_id.split("-")[0], "status": "saved",
                        "results_folder": str(folder), "report": str(folder / "report.html") if (folder / "report.html").exists() else None,
                        "results": load_result_rows(folder)})
    return jsonify({"error": "Scan not found"}), 404

@app.post("/api/scans/<job_id>/stop")
def stop_scan(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Scan not found in current session"}), 404
    proc = job.get("process")
    if not proc or proc.poll() is not None:
        return jsonify({"error": "No active process for this scan"}), 409
    proc.terminate()
    job["status"] = "stopping"
    log_event("Stop requested by user", "WARN", job_id)
    return jsonify({"ok": True})

@app.get("/api/events")
def get_events():
    after = request.args.get("after", type=int, default=0)
    with lock:
        return jsonify({"events": [{"seq": i + 1, **e} for i, e in enumerate(events) if i + 1 > after],
                        "next": len(events)})

@app.get("/api/scans/<job_id>/export.csv")
def export_csv(job_id):
    job = jobs.get(job_id)
    if not job:
        folder = REPORTS_DIR / job_id
        rows = load_result_rows(folder) if folder.is_dir() else []
    else:
        rows = job.get("results", [])
    if not rows:
        return jsonify({"error": "No results to export"}), 404
    import io
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=["subdomain"])
    writer.writeheader()
    writer.writerows({"subdomain": row.get("subdomain", "")} for row in rows)
    from flask import Response
    return Response(stream.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="reconsuite-{job_id}.csv"'})

@app.post("/api/export/pdf")
def export_pdf():
    """Create a compact PDF table containing each subdomain and its live status."""
    payload = request.get_json(silent=True) or {}
    rows = payload.get("rows", [])
    if not isinstance(rows, list) or not rows:
        return jsonify({"error": "No results to export"}), 400
    # Bound payload size and validate fields rather than trusting arbitrary input.
    rows = rows[:20000]
    try:
        from io import BytesIO
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Flowable
    except ImportError:
        return jsonify({"error": "PDF dependency missing. Run: pip install reportlab"}), 500

    class StatusDot(Flowable):
        def __init__(self, live):
            super().__init__()
            self.live = live
            self.width = 9 * mm
            self.height = 5 * mm
        def draw(self):
            self.canv.setFillColor(colors.HexColor("#20b96b") if self.live else colors.HexColor("#e04444"))
            self.canv.circle(2.2 * mm, self.height / 2, 1.35 * mm, stroke=0, fill=1)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=14*mm, leftMargin=14*mm,
                            topMargin=13*mm, bottomMargin=13*mm, title="ReconSuite Lite Subdomain Status")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReconTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                                 fontSize=16, leading=20, alignment=TA_LEFT, textColor=colors.HexColor("#15324b"))
    small_style = ParagraphStyle("ReconSmall", parent=styles["Normal"], fontSize=8, leading=10,
                                 textColor=colors.HexColor("#526273"))
    cell_style = ParagraphStyle("DomainCell", parent=styles["Normal"], fontSize=8, leading=10,
                                textColor=colors.HexColor("#17212b"))
    target = str(payload.get("target", "")).strip()
    story = [Paragraph("ReconSuite Lite — Subdomain Status Report", title_style), Spacer(1, 3*mm)]
    if target:
        story.append(Paragraph("Target: " + target.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), small_style))
    story.append(Paragraph("Green dot = Live host; red dot = Not live / unresolved host.", small_style))
    story.append(Spacer(1, 5*mm))
    table_data = [["Subdomain", "Status"]]
        # Check DNS for each unique hostname during PDF export.
    def check_dns(host):
        host = str(host).strip().rstrip(".")
        try:
            addresses = socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
            return bool(addresses)
        except (socket.gaierror, OSError, ValueError):
            return False

    valid_rows = []
    for item in rows:
        if isinstance(item, dict):
            host = str(item.get("subdomain", "")).strip()
            if host and host not in {"-", "."}:
                valid_rows.append((host, item))

    unique_hosts = list(dict.fromkeys(host for host, _ in valid_rows))

    with ThreadPoolExecutor(max_workers=32) as pool:
        checks = list(pool.map(check_dns, unique_hosts))

    dns_status = dict(zip(unique_hosts, checks))

    table_data = [["Subdomain", "Status"]]

    for host, item in valid_rows:
        live = dns_status[host]
        label = "Live" if live else "Not Live"

        safe_domain = (
            host.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
        )

        status_cell = [
            StatusDot(live),
            Paragraph(label, cell_style),
        ]

        table_data.append([
            Paragraph(safe_domain, cell_style),
            status_cell,
        ])
    if len(table_data) == 1:
        return jsonify({"error": "No valid subdomain rows to export"}), 400
    table = Table(table_data, colWidths=[190*mm, 45*mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#173b58")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 9),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 7),
        ("RIGHTPADDING", (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#cbd5df")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f3f7fa")]),
    ]))
    doc.build(story + [table])
    buffer.seek(0)
    from flask import Response
    return Response(buffer.getvalue(), mimetype="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="reconsuite-subdomains-status.pdf"'})

@app.get("/api/reports")
def reports():
    found = []
    if REPORTS_DIR.exists():
        for folder in sorted((p for p in REPORTS_DIR.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True):
            report = folder / "report.html"
            found.append({"id": folder.name, "folder": str(folder), "name": report.name,
                          "exists": report.exists(), "modified": datetime.fromtimestamp(folder.stat().st_mtime).astimezone().isoformat(timespec="seconds"),
                          "results": len(load_result_rows(folder))})
    return jsonify(found[:100])

@app.delete("/api/reports/<report_id>")
def delete_report(report_id):
    import re
    import shutil

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", report_id):
        return jsonify({"error": "Invalid report ID"}), 400

    reports_root = REPORTS_DIR.resolve()
    folder = (reports_root / report_id).resolve()

    # Prevent deletion outside the reports directory.
    if folder.parent != reports_root:
        return jsonify({"error": "Invalid report path"}), 400

    if not folder.is_dir():
        return jsonify({"error": "Report not found"}), 404

    try:
        shutil.rmtree(folder)

        return jsonify({
            "ok": True,
            "deleted_id": report_id,
            "message": "Report deleted successfully."
        }), 200

    except OSError:
        app.logger.exception("Could not delete report %s", report_id)
        return jsonify({"error": "Could not delete report"}), 500

@app.get("/api/reports/<report_id>/open")
def report_open(report_id):
    """Open a saved HTML report with a separate, reusable PDF toolbar."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", report_id):
        return jsonify({"error": "Invalid report ID"}), 400

    reports_root = REPORTS_DIR.resolve()
    folder = (reports_root / report_id).resolve()
    if folder.parent != reports_root:
        return jsonify({"error": "Invalid report path"}), 400

    report = folder / "report.html"
    if not report.is_file():
        return jsonify({"error": "HTML report not found"}), 404

    toolbar_file = FRONTEND_DIR / "report-toolbar.html"
    if not toolbar_file.is_file():
        app.logger.error("Missing report toolbar: %s", toolbar_file)
        return jsonify({"error": "Report toolbar HTML not found"}), 500

    try:
        report_html = report.read_text(encoding="utf-8")
        toolbar_html = toolbar_file.read_text(encoding="utf-8")
    except OSError:
        app.logger.exception("Could not read report files for %s", report_id)
        return jsonify({"error": "Could not read report files"}), 500

    toolbar_html = toolbar_html.replace("{{REPORT_ID}}", report_id)
    stylesheet = '<link rel="stylesheet" href="/report-pdf.css">'

    if re.search(r"<head(?:\s[^>]*)?>", report_html, flags=re.IGNORECASE):
        report_html = re.sub(
            r"(<head(?:\s[^>]*)?>)",
            lambda match: match.group(1) + stylesheet,
            report_html,
            count=1,
            flags=re.IGNORECASE,
        )
    else:
        report_html = stylesheet + report_html

    if re.search(r"<body(?:\s[^>]*)?>", report_html, flags=re.IGNORECASE):
        report_html = re.sub(
            r"(<body(?:\s[^>]*)?>)",
            lambda match: match.group(1) + toolbar_html,
            report_html,
            count=1,
            flags=re.IGNORECASE,
        )
    else:
        report_html = toolbar_html + report_html

    from flask import Response
    return Response(report_html, mimetype="text/html; charset=utf-8")


@app.get("/report-pdf.css")
def report_pdf_css():
    """Serve the report-only stylesheet; dashboard styles remain untouched."""
    return send_from_directory(FRONTEND_DIR, "report-pdf.css")


@app.get("/api/reports/<report_id>/pdf")
def download_report_pdf(report_id):
    """Build a downloadable PDF from the saved recon results.json."""
    from io import BytesIO
    from xml.sax.saxutils import escape
    from flask import Response

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", report_id):
        return jsonify({"error": "Invalid report ID"}), 400

    reports_root = REPORTS_DIR.resolve()
    folder = (reports_root / report_id).resolve()
    if folder.parent != reports_root:
        return jsonify({"error": "Invalid report path"}), 400

    json_file = folder / "results.json"
    if not json_file.is_file():
        return jsonify({"error": "Report results JSON not found"}), 404

    try:
        payload = json.loads(json_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return jsonify({"error": "Could not read report data"}), 500

    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid report data format"}), 500

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    except ImportError:
        return jsonify({
            "error": "ReportLab is missing. Install it in the application Python environment."
        }), 500

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="Subdomain Recon Report",
        author="ReconSuite Lite",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReconReportTitle", parent=styles["Title"],
        fontSize=19, leading=23, textColor=colors.HexColor("#18212b"),
    )
    body_style = ParagraphStyle(
        "ReconReportBody", parent=styles["BodyText"],
        fontSize=9, leading=12,
    )
    cell_style = ParagraphStyle(
        "ReconReportCell", parent=styles["BodyText"],
        fontSize=8, leading=10, wordWrap="CJK",
    )

    target_raw = str(payload.get("target", "Unknown"))
    target = escape(target_raw)
    generated = escape(str(payload.get("generated_at_utc", "Unknown")))
    total = payload.get("total_unique_subdomains", 0)
    story = [
        Paragraph("Subdomain Recon Report", title_style),
        Spacer(1, 5 * mm),
        Paragraph(
            f"<b>Target:</b> {target}<br/>"
            f"<b>Generated (UTC):</b> {generated}<br/>"
            f"<b>Unique candidate subdomains:</b> {escape(str(total))}",
            body_style,
        ),
        Spacer(1, 5 * mm),
        Paragraph(
            "Passive discovery only. Results may be incomplete or stale. "
            "They do not prove that a host is live or vulnerable. "
            "Assess only assets you own or are authorized to test.",
            body_style,
        ),
        Spacer(1, 6 * mm),
        Paragraph("Tool status", styles["Heading2"]),
    ]

    tool_data = [["Tool", "Status", "Candidates"]]
    tool_results = payload.get("tools", {})
    if isinstance(tool_results, dict):
        for name, info in sorted(tool_results.items()):
            if not isinstance(info, dict):
                info = {}
            tool_data.append([
                Paragraph(escape(str(name)), cell_style),
                Paragraph(escape(str(info.get("status", "Unknown"))), cell_style),
                escape(str(info.get("count", 0))),
            ])
    if len(tool_data) == 1:
        tool_data.append(["No tool information", "", ""])

    tool_table = Table(tool_data, colWidths=[75 * mm, 75 * mm, 55 * mm], repeatRows=1)
    tool_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173b58")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5df")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f7fa")]),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([tool_table, Spacer(1, 7 * mm), Paragraph("Consolidated subdomains", styles["Heading2"])])

    domain_data = [["Subdomain", "Source tool(s)"]]
    subdomains = payload.get("subdomains", [])
    if isinstance(subdomains, list):
        for item in subdomains:
            if not isinstance(item, dict):
                continue
            host = escape(str(item.get("subdomain", "")))
            sources_value = item.get("sources", [])
            if isinstance(sources_value, list):
                sources = ", ".join(str(source) for source in sources_value)
            else:
                sources = str(sources_value)
            domain_data.append([
                Paragraph(host, cell_style),
                Paragraph(escape(sources), cell_style),
            ])
    if len(domain_data) == 1:
        domain_data.append(["No subdomains found", ""])

    domain_table = Table(domain_data, colWidths=[170 * mm, 65 * mm], repeatRows=1)
    domain_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173b58")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5df")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f7fa")]),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(domain_table)
    doc.build(story)
    buffer.seek(0)

    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target_raw).strip("._-") or "report"
    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="ReconSuite-{safe_target}-Report.pdf"'},
    )





if __name__ == "__main__":
    # Local-only API. Do not expose this development server to the network.
    app.run(host="127.0.0.1", port=int(os.environ.get("RECONSUITE_PORT", "8765")),
            debug=False, threaded=True)
