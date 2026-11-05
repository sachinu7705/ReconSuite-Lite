
import argparse
import csv
import html
import json
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

TOOLS = ("subfinder", "amass", "theHarvester", "assetfinder", "crtsh")

HOST_RE = re.compile(
    r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])"
)


def normalize_domain(value):
    value = value.strip()

    if "://" in value:
        value = urlparse(value).hostname or ""

    value = value.split("/")[0].split(":")[0].strip().rstrip(".").lower()

    if value.startswith("*."):
        value = value[2:]

    if value.startswith("www."):
        value = value[4:]

    pattern = (
        r"(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}"
    )

    if not re.fullmatch(pattern, value):
        raise argparse.ArgumentTypeError(
            "Enter a valid domain, e.g. example.com"
        )

    return value


def run_command_tool(name, domain, outdir):
    executable = shutil.which(name)

    if not executable:
        return name, [], "not installed"

    if name == "subfinder":
        command = [executable, "-d", domain, "-silent"]
    elif name == "amass":
        command = [executable, "enum", "-passive", "-d", domain]
    elif name == "assetfinder":
        command = [executable, "--subs-only", domain]
    elif name == "theHarvester":
        # Use theHarvester's actual domain-search options.
        command = [
            executable, "-d", domain, "-b", "crtsh"
        ]
    else:
        return name, [], "unsupported command-line tool"

    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=900,
            check=False,
        )

        output = process.stdout or ""
        (outdir / f"{name}.log").write_text(
            output, encoding="utf-8", errors="replace"
        )

        hosts = {
            match.lower().rstrip(".")
            for match in HOST_RE.findall(output)
            if match.lower().rstrip(".") == domain
            or match.lower().rstrip(".").endswith("." + domain)
        }

        status = (
            "completed"
            if process.returncode == 0
            else f"exit code {process.returncode}"
        )
        return name, sorted(hosts), status

    except subprocess.TimeoutExpired:
        return name, [], "timed out after 15 minutes"
    except OSError as exc:
        return name, [], f"error: {exc}"


def run_crtsh(domain, outdir):
    """Retrieve passive certificate-transparency names from crt.sh."""
    name = "crtsh"
    url = (
        "https://crt.sh/?"
        + urllib.parse.urlencode({
            "q": "%." + domain,
            "output": "json",
        })
    )

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ReconSuite-Lite/1.0"},
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8", errors="replace")

        (outdir / "crtsh.log").write_text(
            raw, encoding="utf-8", errors="replace"
        )

        records = json.loads(raw)
        hosts = set()

        for record in records:
            for entry in str(record.get("name_value", "")).splitlines():
                host = entry.strip().lower().rstrip(".")

                if host.startswith("*."):
                    host = host[2:]

                if (
                    HOST_RE.fullmatch(host)
                    and (host == domain or host.endswith("." + domain))
                ):
                    hosts.add(host)

        return name, sorted(hosts), "completed"

    except urllib.error.HTTPError as exc:
        return name, [], f"HTTP error {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return name, [], f"network error: {exc}"
    except (json.JSONDecodeError, UnicodeError) as exc:
        return name, [], f"invalid response: {exc}"


def run_tool(name, domain, outdir):
    # Report the real start of each parallel tool.
    print(f"[TOOL_START] {name}", flush=True)

    try:
        if name == "crtsh":
            result = run_crtsh(domain, outdir)
        else:
            result = run_command_tool(name, domain, outdir)

        tool_name, hosts, status = result
        final_state = "completed" if status == "completed" else "failed"

    except Exception as exc:
        tool_name, hosts = name, []
        status = f"error: {exc}"
        final_state = "failed"

    # Report the real end of the tool.
    print(f"[TOOL_DONE] {tool_name} {final_state}", flush=True)

    return tool_name, hosts, status


def main():
    parser = argparse.ArgumentParser(
        description="Passive subdomain discovery and reporting."
    )
    parser.add_argument(
        "domain",
        type=normalize_domain,
        help="Domain you own or are authorized to assess",
    )
    parser.add_argument(
        "-o", "--output",
        default="recon-reports",
        help="Output directory",
    )
    parser.add_argument(
        "--tools",
        default="subfinder,amass,theHarvester,assetfinder,crtsh",
        help="Comma-separated tools: " + ",".join(TOOLS),
    )

    args = parser.parse_args()
    domain = args.domain

    outdir = (
        Path(args.output).expanduser().resolve()
        / f"{domain}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
    outdir.mkdir(parents=True, exist_ok=True)

    selected = list(dict.fromkeys(
        item.strip() for item in args.tools.split(",") if item.strip()
    ))
    invalid = sorted(set(selected) - set(TOOLS))

    if invalid or not selected:
        parser.error("Invalid --tools selection. Choose from: " + ", ".join(TOOLS))

    print(f"[*] Target domain: {domain}")
    print("[*] Running selected passive discovery sources.")

    results = {}

    with ThreadPoolExecutor(max_workers=len(selected)) as pool:
        futures = {
            pool.submit(run_tool, name, domain, outdir): name
            for name in selected
        }

        for future in as_completed(futures):
            name = futures[future]
            try:
                tool_name, hosts, status = future.result()
            except Exception as exc:
                tool_name, hosts, status = name, [], f"error: {exc}"

            results[tool_name] = {
                "status": status,
                "count": len(hosts),
                "hosts": hosts,
            }
            print(f"[*] {tool_name}: {status}; {len(hosts)} candidate(s)")

    host_sources = {}

    for tool_name, info in results.items():
        for host in info["hosts"]:
            host_sources.setdefault(host, set()).add(tool_name)

    hosts = sorted(host_sources)

    payload = {
        "target": domain,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "passive",
        "total_unique_subdomains": len(hosts),
        "tools": results,
        "subdomains": [
            {
                "subdomain": host,
                "sources": sorted(host_sources[host]),
                "status": "Unknown",
            }
            for host in hosts
        ],
        "note": (
            "Discovery results are candidates, not proof of liveness "
            "or vulnerability. Validate only within authorized scope."
        ),
    }

    (outdir / "subdomains.txt").write_text(
        "".join(host + "\n" for host in hosts), encoding="utf-8"
    )
    (outdir / "results.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )

    with (outdir / "results.csv").open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["subdomain", "source_tools"])
        for host in hosts:
            writer.writerow([
                host, ", ".join(sorted(host_sources[host]))
            ])

    rows = "".join(
        "<tr><td>" + html.escape(host) + "</td><td>"
        + html.escape(", ".join(sorted(host_sources[host])))
        + "</td></tr>"
        for host in hosts
    ) or '<tr><td colspan="2">No subdomains found.</td></tr>'

    tool_rows = "".join(
        "<tr><td>" + html.escape(name) + "</td><td>"
        + html.escape(info["status"]) + "</td><td>"
        + str(info["count"]) + "</td></tr>"
        for name, info in sorted(results.items())
    )

    report = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>Subdomain Recon Report — {html.escape(domain)}</title>
<style>
body{{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#18212b}}
h1{{overflow-wrap:anywhere}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ccd3da;padding:.55rem;text-align:left;overflow-wrap:anywhere}}
th{{background:#eef2f6}}
.note{{padding:1rem;background:#f5f7fa;border-left:4px solid #667085}}
</style>
</head>
<body>
<h1>Subdomain Recon Report</h1>
<p><b>Target:</b> {html.escape(domain)}<br>
<b>Generated (UTC):</b> {html.escape(payload["generated_at_utc"])}<br>
<b>Unique candidates:</b> {len(hosts)}</p>
<div class="note">Passive discovery only. Results may be incomplete or stale. They do not prove a host is live or vulnerable.</div>
<h2>Tool status</h2>
<table><thead><tr><th>Tool</th><th>Status</th><th>Candidates</th></tr></thead>
<tbody>{tool_rows}</tbody></table>
<h2>Consolidated subdomains</h2>
<table><thead><tr><th>Subdomain</th><th>Source tools</th></tr></thead>
<tbody>{rows}</tbody></table>
<p>Companion files: subdomains.txt, results.csv, results.json. Individual logs are retained.</p>
</body>
</html>"""

    (outdir / "report.html").write_text(report, encoding="utf-8")

    print(f"\n[+] Unique candidate subdomains: {len(hosts)}")
    print(f"[+] HTML report: {outdir / 'report.html'}")
    print(f"[+] Text list: {outdir / 'subdomains.txt'}")
    print(f"[+] CSV / JSON: {outdir / 'results.csv'} ; {outdir / 'results.json'}")


if __name__ == "__main__":
    main()
