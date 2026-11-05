import re

import dns.exception
import dns.resolver

from flask import Blueprint, jsonify, request

dns_api = Blueprint("dns_api", __name__)

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def validate_domain(domain):
    domain = domain.strip().rstrip(".")

    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(domain) > 253 or not domain:
        return None

    labels = domain.split(".")

    if len(labels) < 2:
        return None

    for label in labels:
        if (
            len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            return None

    return domain


def format_record(record_type, record):
    if record_type == "MX":
        return {
            "priority": record.preference,
            "exchange": str(record.exchange).rstrip(".")
        }

    if record_type == "SOA":
        return {
            "primary_nameserver": str(record.mname).rstrip("."),
            "responsible_email": str(record.rname).rstrip("."),
            "serial": record.serial,
            "refresh": record.refresh,
            "retry": record.retry,
            "expire": record.expire,
            "minimum": record.minimum
        }

    if record_type == "TXT":
        return record.to_text()

    return str(record).rstrip(".")


@dns_api.get("/api/dns/lookup")
def dns_lookup():
    raw_domain = request.args.get("domain", "")
    domain = validate_domain(raw_domain)

    if not domain:
        return jsonify({
            "ok": False,
            "error": "Enter a valid domain name."
        }), 400

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    results = []
    errors = []

    for record_type in RECORD_TYPES:
        try:
            answer = resolver.resolve(
                domain,
                record_type,
                raise_on_no_answer=False
            )

            if answer.rrset is None:
                continue

            values = [
                format_record(record_type, record)
                for record in answer
            ]

            results.append({
                "type": record_type,
                "ttl": answer.rrset.ttl,
                "count": len(values),
                "values": values
            })

        except dns.resolver.NXDOMAIN:
            return jsonify({
                "ok": False,
                "domain": domain,
                "error": "Domain does not exist."
            }), 404

        except dns.resolver.NoAnswer:
            continue

        except dns.resolver.NoNameservers:
            errors.append({
                "type": record_type,
                "message": "No responding DNS nameservers."
            })

        except dns.exception.Timeout:
            errors.append({
                "type": record_type,
                "message": "DNS query timed out."
            })

        except Exception:
            errors.append({
                "type": record_type,
                "message": "Could not retrieve this record."
            })

    return jsonify({
        "ok": True,
        "domain": domain,
        "records": results,
        "record_types_checked": list(RECORD_TYPES),
        "total_records": sum(item["count"] for item in results),
        "errors": errors
    }), 200


# ---------------- WHOIS LOOKUP API ----------------

import re
import whois
from datetime import date, datetime


def normalize_whois_value(value):
    """Convert WHOIS values into JSON-safe data."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, (list, tuple, set)):
        return [normalize_whois_value(item) for item in value]

    if isinstance(value, dict):
        return {
            str(key): normalize_whois_value(item)
            for key, item in value.items()
        }

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    return str(value)


@dns_api.get("/api/whois/lookup")
def whois_lookup():
    domain = request.args.get("domain", "").strip().lower()

    if not domain:
        return jsonify({"ok": False, "error": "Domain is required."}), 400

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return jsonify({"ok": False, "error": "Invalid domain name."}), 400

    if (
        len(domain) > 253
        or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
            domain
        )
    ):
        return jsonify({"ok": False, "error": "Invalid domain name."}), 400

    try:
        result = whois.whois(domain)

        if not result:
            return jsonify({
                "ok": False,
                "error": "No WHOIS information was returned."
            }), 404

        data = dict(result)

        fields = [
            "domain_name",
            "registrar",
            "whois_server",
            "creation_date",
            "expiration_date",
            "updated_date",
            "status",
            "name_servers",
            "emails",
            "org",
            "country",
            "registrant",
            "registrant_country",
        ]

        details = {
            key: normalize_whois_value(data.get(key))
            for key in fields
            if data.get(key) is not None
        }

        return jsonify({
            "ok": True,
            "domain": domain,
            "details": details
        })

    except Exception as error:
        return jsonify({
            "ok": False,
            "domain": domain,
            "error": str(error)
        }), 502


# ---------------- WHOIS PDF EXPORT ----------------

@dns_api.get("/api/whois/pdf")
def whois_pdf():
    from io import BytesIO
    from flask import send_file
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from xml.sax.saxutils import escape

    domain = request.args.get("domain", "").strip().lower()

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return jsonify({"ok": False, "error": "Invalid domain."}), 400

    if (
        len(domain) > 253
        or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
            domain
        )
    ):
        return jsonify({"ok": False, "error": "Invalid domain."}), 400

    try:
        result = whois.whois(domain)

        if not result:
            return jsonify({
                "ok": False,
                "error": "No WHOIS information available."
            }), 404

        details = {
            key: normalize_whois_value(value)
            for key, value in dict(result).items()
            if value is not None
        }

        buffer = BytesIO()

        pdf = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=20,
            textColor=colors.HexColor("#0879c9"),
            alignment=TA_CENTER,
            spaceAfter=8
        )

        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#0879c9"),
            spaceBefore=12,
            spaceAfter=8
        )

        story = [
            Paragraph("ReconSuite Lite", title_style),
            Paragraph("WHOIS Domain Intelligence Report", styles["Heading2"]),
            Spacer(1, 8),
            Paragraph(f"<b>Domain:</b> {escape(domain)}", styles["Normal"]),
            Paragraph(
                "<b>Generated:</b> "
                + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                styles["Normal"]
            ),
            Spacer(1, 15),
            Paragraph("Registration Information", heading_style)
        ]

        rows = [["FIELD", "VALUE"]]

        for key, value in details.items():
            label = key.replace("_", " ").title()
            text_value = format_pdf_value(value)

            # Keep long values readable and prevent HTML interpretation.
            safe_value = escape(text_value).replace("\n", "<br/>")

            rows.append([
                Paragraph(f"<b>{escape(label)}</b>", styles["BodyText"]),
                Paragraph(safe_value, styles["BodyText"])
            ])

        table = Table(
            rows,
            colWidths=[48 * mm, 125 * mm],
            repeatRows=1
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12314a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f1f5f9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white, colors.HexColor("#f1f5f9")
            ]),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))

        story.append(table)
        story.append(Spacer(1, 15))
        story.append(Paragraph(
            "Note: WHOIS data is supplied by external registration "
            "databases. Some registrant information may be hidden, "
            "redacted, or unavailable.",
            styles["Italic"]
        ))

        pdf.build(story)
        buffer.seek(0)

        filename = f"whois-{domain}.pdf"

        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 502


def format_pdf_value(value):
    if isinstance(value, list):
        return "\n".join(format_pdf_value(item) for item in value)

    if isinstance(value, dict):
        return "\n".join(
            f"{key}: {format_pdf_value(item)}"
            for key, item in value.items()
        )

    # ReportLab's built-in Helvetica font has limited Unicode support.
    return str(value).encode("latin-1", errors="replace").decode("latin-1")


# ---------------- DNS PDF EXPORT ----------------

@dns_api.get("/api/dns/pdf")
def dns_pdf():
    from io import BytesIO
    from flask import send_file
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from xml.sax.saxutils import escape

    domain = request.args.get("domain", "").strip().lower()

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return jsonify({"ok": False, "error": "Invalid domain."}), 400

    if (
        len(domain) > 253
        or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
            domain
        )
    ):
        return jsonify({"ok": False, "error": "Invalid domain."}), 400

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        records = []
        errors = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                ttl = answers.rrset.ttl if answers.rrset else None
                values = []

                for item in answers:
                    if record_type == "MX":
                        values.append({
                            "exchange": str(item.exchange).rstrip("."),
                            "priority": item.preference
                        })

                    elif record_type == "SOA":
                        values.append({
                            "primary_nameserver": str(item.mname).rstrip("."),
                            "responsible_email": str(item.rname).rstrip("."),
                            "serial": item.serial,
                            "refresh": item.refresh,
                            "retry": item.retry,
                            "expire": item.expire,
                            "minimum": item.minimum
                        })

                    elif record_type == "TXT":
                        values.append(item.to_text())

                    else:
                        values.append(str(item).rstrip("."))

                if values:
                    records.append({
                        "type": record_type,
                        "ttl": ttl,
                        "values": values
                    })

            except Exception as error:
                errors.append({
                    "type": record_type,
                    "error": str(error)
                })

        buffer = BytesIO()

        pdf = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "DNSTitle",
            parent=styles["Title"],
            fontSize=21,
            textColor=colors.HexColor("#0879c9"),
            alignment=1,
            spaceAfter=10
        )

        story = [
            Paragraph("ReconSuite Lite", title_style),
            Paragraph("DNS Intelligence Report", styles["Heading2"]),
            Spacer(1, 8),
            Paragraph(f"<b>Domain:</b> {escape(domain)}", styles["Normal"]),
            Paragraph(
                "<b>Generated:</b> "
                + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                styles["Normal"]
            ),
            Spacer(1, 12),
            Paragraph("DNS Lookup Summary", styles["Heading2"]),
            Paragraph(f"<b>Total Records:</b> {sum(len(r['values']) for r in records)}", styles["Normal"]),
            Paragraph(f"<b>Record Types Found:</b> {len(records)}", styles["Normal"]),
            Paragraph(f"<b>Query Errors:</b> {len(errors)}", styles["Normal"]),
            Spacer(1, 15),
            Paragraph("DNS Records", styles["Heading2"])
        ]

        rows = [["TYPE", "VALUE", "TTL"]]

        for record in records:
            for value in record["values"]:
                if isinstance(value, dict):
                    value_text = "\n".join(
                        f"{key}: {item}" for key, item in value.items()
                    )
                else:
                    value_text = str(value)

                rows.append([
                    Paragraph(escape(record["type"]), styles["BodyText"]),
                    Paragraph(
                        escape(value_text).replace("\n", "<br/>"),
                        styles["BodyText"]
                    ),
                    Paragraph(
                        escape(str(record["ttl"] or "N/A")),
                        styles["BodyText"]
                    )
                ])

        table = Table(
            rows,
            colWidths=[25 * mm, 130 * mm, 20 * mm],
            repeatRows=1
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12314a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white, colors.HexColor("#f1f5f9")
            ]),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))

        story.append(table)

        if errors:
            story.extend([
                Spacer(1, 15),
                Paragraph("Query Errors", styles["Heading2"])
            ])

            for error in errors:
                story.append(Paragraph(
                    f"<b>{escape(error['type'])}:</b> "
                    f"{escape(error['error'])}",
                    styles["BodyText"]
                ))

        story.extend([
            Spacer(1, 18),
            Paragraph(
                "Note: DNS records can change over time. "
                "This report reflects the results collected when generated.",
                styles["Italic"]
            )
        ])

        pdf.build(story)
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"dns-{domain}.pdf"
        )

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 502
