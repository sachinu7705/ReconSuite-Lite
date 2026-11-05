"""Read-only AI analysis endpoints for ReconSuite Lite."""
import json
import sqlite3
from pathlib import Path

from flask import Blueprint, jsonify, request

try:
    from .ai_service import ask_ollama, AIServiceError
    from .port_history import get_scan
except ImportError:
    from ai_service import ask_ollama, AIServiceError
    from port_history import get_scan

ai_api = Blueprint("ai_api", __name__)

BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent
try:
    from .storage import get_database_path
except ImportError:
    from storage import get_database_path

VULN_DB = get_database_path("vulnerability_history.db")
REPORTS_DIR = Path(__import__("os").environ.get(
    "RECONSUITE_REPORTS",
    str(ROOT_DIR / "recon-reports"),
)).expanduser().resolve()


def run_analysis(message, evidence):
    try:
        result = ask_ollama(message, evidence)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except AIServiceError as exc:
        return jsonify({"error": str(exc)}), 502


@ai_api.get("/api/ai/health")
def ai_health():
    return jsonify({
        "service": "local-ollama",
        "model": __import__("os").environ.get(
            "RECONSUITE_AI_MODEL", "qwen2.5-coder:1.5b"
        ),
        "analysis_only": True,
    })


@ai_api.post("/api/ai/chat")
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    evidence = data.get("evidence", {})

    if not isinstance(evidence, (dict, list, str)):
        return jsonify({"error": "Evidence must be JSON-compatible data."}), 400

    return run_analysis(message, evidence)


@ai_api.post("/api/ai/analyze/vulnerability/<assessment_id>")
def analyze_vulnerability(assessment_id):
    with sqlite3.connect(VULN_DB) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """SELECT id, target, status, created_at, findings
               FROM assessments WHERE id = ?""",
            (assessment_id,),
        ).fetchone()

    if row is None:
        return jsonify({"error": "Assessment not found."}), 404

    try:
        findings = json.loads(row["findings"] or "[]")
    except json.JSONDecodeError:
        return jsonify({"error": "Stored findings are invalid JSON."}), 500

    evidence = {
        "type": "saved_vulnerability_assessment",
        "assessment": {
            "id": row["id"],
            "target": row["target"],
            "status": row["status"],
            "created_at": row["created_at"],
            "findings": findings,
        },
    }

    return run_analysis(
        "Analyze these saved vulnerability findings. Prioritize risks, "
        "explain confidence and limitations, and recommend remediation. "
        "Do not initiate further tests.",
        evidence,
    )


@ai_api.post("/api/ai/analyze/port-scan/<scan_id>")
def analyze_port_scan(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Saved port scan not found."}), 404

    evidence = {
        "type": "saved_port_scan",
        "scan": scan,
    }

    return run_analysis(
        "Interpret this saved port scan. Explain likely service exposure, "
        "risk and defensive next steps. An open port alone is not proof of "
        "a vulnerability. Do not initiate further tests.",
        evidence,
    )


@ai_api.post("/api/ai/analyze/recon/<report_id>")
def analyze_recon(report_id):
    # Restrict access to a single report directory directly below REPORTS_DIR.
    if (
        not report_id
        or report_id in (".", "..")
        or "/" in report_id
        or "\\" in report_id
    ):
        return jsonify({"error": "Invalid report ID."}), 400

    report_dir = (REPORTS_DIR / report_id).resolve()
    if report_dir.parent != REPORTS_DIR:
        return jsonify({"error": "Invalid report path."}), 400

    results_file = report_dir / "results.json"
    if not results_file.is_file():
        return jsonify({"error": "Recon results JSON not found."}), 404

    try:
        results = json.loads(results_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return jsonify({"error": "Could not read valid recon results."}), 500

    evidence = {
        "type": "saved_recon_results",
        "report_id": report_id,
        "results": results,
    }

    return run_analysis(
        "Analyze these existing reconnaissance results. Summarize observed "
        "assets, identify defensive priorities and uncertainties, and suggest "
        "safe follow-up steps. Do not perform additional discovery.",
        evidence,
    )
