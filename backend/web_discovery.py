from flask import Blueprint, jsonify, request
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import requests
import socket
import ipaddress
import re

web_api = Blueprint("web_api", __name__)

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 12

SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer Policy",
    "Permissions-Policy": "Permissions Policy"
}


def validate_target(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("A valid hostname is required.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid port.")

    hostname = parsed.hostname.rstrip(".")

    if hostname.lower() in ("localhost",):
        raise ValueError("Localhost targets are not allowed.")

    try:
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("Could not resolve the target hostname.")

    if not addresses:
        raise ValueError("No IP addresses found.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError(
                "Private, local, reserved and non-public IP addresses are blocked."
            )

    return parsed


def detect_technologies(headers, html):
    detected = set()

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")

    if server:
        detected.add("Server: " + server)

    if powered:
        detected.add("Powered By: " + powered)

    patterns = {
        "WordPress": r"wp-content|wp-includes",
        "Drupal": r"drupal-settings-json|/sites/default/",
        "Joomla": r"joomla",
        "React": r"react|reactroot|_reactRootContainer",
        "Next.js": r"_next/static|__next",
        "Vue.js": r"vue\.js|__vue__",
        "Angular": r"ng-version|angular",
        "Bootstrap": r"bootstrap\.min\.(css|js)",
        "jQuery": r"jquery",
        "Tailwind CSS": r"tailwindcss"
    }

    for technology, pattern in patterns.items():
        if re.search(pattern, html, re.IGNORECASE):
            detected.add(technology)

    return sorted(detected)


@web_api.post("/api/web-discovery/scan")
def scan_website():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()

    if not url:
        return jsonify({"ok": False, "error": "Website URL is required."}), 400

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = validate_target(url)

        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": "ReconSuiteLite-WebDiscovery/1.0",
                "Accept": "text/html,application/xhtml+xml"
            }
        )

        if 300 <= response.status_code < 400:
            location = response.headers.get("Location", "")
            response.close()

            return jsonify({
                "ok": False,
                "error": "The website redirected the request. "
                         "Enter the destination URL directly.",
                "redirect_location": location
            }), 400

        content_type = response.headers.get("Content-Type", "")

        if "text/html" not in content_type.lower() and \
           "application/xhtml+xml" not in content_type.lower():
            response.close()
            return jsonify({
                "ok": False,
                "error": "The target did not return an HTML page.",
                "status_code": response.status_code,
                "content_type": content_type
            }), 415

        content = response.raw.read(MAX_BYTES + 1)
        response.close()

        if len(content) > MAX_BYTES:
            content = content[:MAX_BYTES]

        encoding = response.encoding or "utf-8"
        html = content.decode(encoding, errors="replace")

        soup = BeautifulSoup(html, "html.parser")

        title = soup.title.get_text(" ", strip=True) if soup.title else ""

        description_tag = soup.find(
            "meta", attrs={"name": re.compile("^description$", re.I)}
        )

        description = (
            description_tag.get("content", "")
            if description_tag else ""
        )

        canonical_tag = soup.find("link", rel="canonical")
        canonical = canonical_tag.get("href", "") if canonical_tag else ""

        headers = dict(response.headers)

        security_headers = {}

        for header, label in SECURITY_HEADERS.items():
            value = headers.get(header)

            security_headers[label] = {
                "present": bool(value),
                "value": value or "Missing"
            }

        internal_links = set()
        external_links = set()
        discovered_paths = set()

        base_host = parsed.hostname.lower()

        for link in soup.find_all("a", href=True):
            href = link.get("href", "").strip()

            if not href or href.startswith(
                ("javascript:", "mailto:", "tel:", "data:")
            ):
                continue

            absolute = urldefrag(urljoin(url, href))[0]
            link_parsed = urlparse(absolute)

            if link_parsed.scheme not in ("http", "https"):
                continue

            if link_parsed.hostname and \
               link_parsed.hostname.lower() == base_host:
                internal_links.add(absolute)

                path = link_parsed.path or "/"
                if path != "/":
                    discovered_paths.add(path)
            else:
                external_links.add(absolute)

        technologies = detect_technologies(headers, html)

        return jsonify({
            "ok": True,
            "target": url,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "website": {
                "status_code": response.status_code,
                "reason": response.reason,
                "final_url": response.url,
                "content_type": content_type,
                "server": headers.get("Server", "Not disclosed"),
                "content_length": len(content),
                "title": title,
                "description": description,
                "canonical": canonical
            },
            "security_headers": security_headers,
            "technologies": technologies,
            "links": {
                "internal": sorted(internal_links),
                "external": sorted(external_links),
                "internal_count": len(internal_links),
                "external_count": len(external_links)
            },
            "discovered_paths": sorted(discovered_paths)
        })

    except ValueError as error:
        return jsonify({"ok": False, "error": str(error)}), 400

    except requests.Timeout:
        return jsonify({
            "ok": False,
            "error": "Website request timed out."
        }), 504

    except requests.RequestException as error:
        return jsonify({
            "ok": False,
            "error": f"Website request failed: {error}"
        }), 502

    except Exception as error:
        return jsonify({
            "ok": False,
            "error": str(error)
        }), 500
