from datetime import datetime
from flask import send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
import csv
import io
import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from flask import Blueprint, jsonify, request, Response
try:
    from .port_history import (
        init_history,
        save_scan,
        get_scan,
        list_scans,
        delete_scan
    )
except ImportError:
    from port_history import (
        init_history,
        save_scan,
        get_scan,
        list_scans,
        delete_scan
    )

port_api = Blueprint("port_api", __name__)

init_history()

scan_lock = threading.Lock()
port_jobs = {}

COMMON_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,"
    "443,445,993,995,1723,3306,3389,5900,8080,8443"
)


def validate_target(value):
    target = str(value or "").strip()

    if not target or len(target) > 253:
        raise ValueError("Enter a valid IP address or hostname.")

    if any(c.isspace() for c in target) or "://" in target or "/" in target:
        raise ValueError("Enter a hostname or IP address, not a URL.")

    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass

    if target.endswith("."):
        target = target[:-1]

    if not target or len(target) > 253:
        raise ValueError("Invalid hostname.")

    try:
        socket.inet_aton(target)
    except OSError:
        pass
    else:
        raise ValueError("Enter a valid IP address or hostname.")

    labels = target.split(".")
    if any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid hostname format.")

    return target


def parse_ports(mode, custom):
    if mode == "common":
        return COMMON_PORTS
    if mode == "1-1024":
        return "1-1024"
    if mode != "custom":
        raise ValueError("Unknown port selection.")

    custom = str(custom or "").strip()
    if not custom or len(custom) > 500:
        raise ValueError("Enter a valid custom port list.")

    ports = set()

    for item in custom.split(","):
        item = item.strip()

        if re.fullmatch(r"\d+", item):
            start = end = int(item)
        else:
            match = re.fullmatch(r"(\d+)-(\d+)", item)
            if not match:
                raise ValueError("Use ports like 22,80,443 or 8000-8100.")
            start, end = map(int, match.groups())

        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError("Ports must be between 1 and 65535.")
        if start > end:
            raise ValueError("Port ranges must start before they end.")

        if end - start > 1999:
            raise ValueError("A single custom range may contain at most 2000 ports.")

        ports.update(range(start, end + 1))
        if len(ports) > 2000:
            raise ValueError("A scan may include at most 2000 ports.")

    return ",".join(map(str, sorted(ports)))


def scan_worker(job_id, target, ports, version_detection):
    job = port_jobs[job_id]
    process = None

    try:
        command = [
            shutil.which("nmap"),
            "-n",
            "-T3",
            "--open",
            "-oX",
            "-",
            "-p",
            ports,
        ]

        if version_detection:
            command.append("-sV")

        command.append(target)

        job.update(status="running", started_at=time.time())
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        job["process"] = process

        stdout, stderr = process.communicate(timeout=300)

        if job.get("stop_requested"):
            job.update(status="stopped", finished_at=time.time())
            return

        if process.returncode != 0:
            raise RuntimeError((stderr or "Nmap failed.").strip()[:1000])

        root = ET.fromstring(stdout)
        results = []

        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")

                results.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol", "tcp"),
                    "state": state.get("state", "unknown") if state is not None else "unknown",
                    "service": service.get("name", "unknown") if service is not None else "unknown",
                    "version": " ".join(
                        service.get(k, "")
                        for k in ("product", "version", "extrainfo")
                        if service is not None and service.get(k)
                    ),
                })

        job.update(
            status="completed",
            results=results,
            finished_at=time.time(),
            message=f"Scan completed. {len(results)} open port(s) found.",
        )
        save_scan(job)

    except subprocess.TimeoutExpired:
        if process:
            process.kill()
            process.communicate()
        job.update(status="error", message="Scan timed out after 300 seconds.")
    except Exception as exc:
        job.update(status="error", message=str(exc)[:1000])
    finally:
        job.pop("process", None)


@port_api.post("/api/port-scans")
def start_port_scan():
    if not shutil.which("nmap"):
        return jsonify({"error": "Nmap is not installed or is not on PATH."}), 500

    data = request.get_json(silent=True) or {}

    try:
        target = validate_target(data.get("target"))
        ports = parse_ports(data.get("ports"), data.get("custom_ports"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    version_detection = data.get("version_detection") is True
    job_id = uuid.uuid4().hex

    with scan_lock:
        port_jobs[job_id] = {
            "id": job_id,
            "target": target,
            "status": "queued",
            "results": [],
            "message": "Scan queued.",
            "created_at": time.time(),
        }

    threading.Thread(
        target=scan_worker,
        args=(job_id, target, ports, version_detection),
        daemon=True,
    ).start()

    return jsonify({"id": job_id, "status": "queued"}), 202


@port_api.get("/api/port-scans/<job_id>")
def get_port_scan(job_id):
    job = port_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Scan not found."}), 404

    return jsonify({
        "id": job["id"],
        "target": job["target"],
        "status": job["status"],
        "results": job["results"],
        "message": job["message"],
        "elapsed": round(time.time() - job["created_at"], 1),
    })


@port_api.post("/api/port-scans/<job_id>/stop")
def stop_port_scan(job_id):
    job = port_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Scan not found."}), 404

    if job["status"] not in ("queued", "running"):
        return jsonify({"error": "Scan is not running."}), 409

    job["stop_requested"] = True
    process = job.get("process")

    if process and process.poll() is None:
        process.terminate()

    job.update(status="stopped", message="Scan stopped by user.", finished_at=time.time())
    return jsonify({"status": "stopped"})


@port_api.get("/api/port-scans/<job_id>/export.csv")
def export_port_scan(job_id):
    job = port_jobs.get(job_id) or get_scan(job_id)
    if not job:
        return jsonify({"error": "Scan not found."}), 404

    stream = io.StringIO()
    fields = ["port", "protocol", "state", "service", "version"]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    writer.writerows(job["results"])

    return Response(
        stream.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="port-scan-{job_id}.csv"'
        },
    )

@port_api.get("/api/port-scans/<job_id>/export.pdf")
def export_port_scan_pdf(job_id):
    job = port_jobs.get(job_id) or get_scan(job_id)

    if not job:
        return jsonify({"error": "Scan not found."}), 404

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("ReconSuite Lite — Port Scan Report", styles["Title"]))
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(
        f"<b>Target:</b> {job['target']}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"<b>Status:</b> {job['status']}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"<b>Generated:</b> {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"<b>Open ports recorded:</b> {len(job.get('results', []))}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 8 * mm))

    rows = [["Port", "Protocol", "State", "Service", "Version"]]

    for result in job.get("results", []):
        rows.append([
            str(result.get("port", "")),
            str(result.get("protocol", "")),
            str(result.get("state", "")),
            str(result.get("service", "")),
            str(result.get("version", "")) or "—",
        ])

    if len(rows) == 1:
        rows.append(["—", "—", "—", "No open ports recorded", "—"])

    table = Table(
        rows,
        repeatRows=1,
        colWidths=[25 * mm, 25 * mm, 25 * mm, 45 * mm, 105 * mm],
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243247")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F1F5F9"),
        ]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(table)
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "This report contains scan results recorded by ReconSuite Lite. "
        "Review findings in the context of your authorized assessment.",
        styles["Italic"],
    ))

    doc.build(story)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"port-scan-{job_id}.pdf",
    )



@port_api.get("/api/port-scans/history")
def port_scan_history():
    return jsonify(list_scans())


@port_api.get("/api/port-scans/history/<scan_id>")
def port_scan_history_detail(scan_id):
    scan = get_scan(scan_id)

    if not scan:
        return jsonify({"error": "History record not found."}), 404

    return jsonify(scan)


@port_api.delete("/api/port-scans/<scan_id>")
def delete_port_scan(scan_id):
    # Validate the UUID generated by the scanner.
    if (
        len(scan_id) != 32
        or any(c not in "0123456789abcdefABCDEF" for c in scan_id)
    ):
        return jsonify({"error": "Invalid scan ID."}), 400

    with scan_lock:
        job = port_jobs.get(scan_id)

        # Do not delete a scan while its process is running.
        if job and job.get("status") in ("queued", "running"):
            return jsonify({
                "error": "Stop the scan before deleting it."
            }), 409

        deleted = delete_scan(scan_id)

        if not deleted:
            return jsonify({"error": "Scan not found."}), 404

        port_jobs.pop(scan_id, None)

    return jsonify({
        "ok": True,
        "deleted_id": scan_id,
        "message": "Port scan deleted successfully."
    }), 200

