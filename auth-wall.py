#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import httpx

console = Console()

def hash_content(content):
    return hashlib.md5(content.encode(errors="ignore")).hexdigest()

async def fetch_url(url, headers, client):
    try:
        resp = await client.get(url, headers=headers, timeout=10)
        return {
            "url": url,
            "status": resp.status_code,
            "length": len(resp.content),
            "content_type": resp.headers.get("content-type", "N/A"),
            "content_hash": hash_content(resp.text),
            "error": None
        }
    except Exception as e:
        return {
            "url": url,
            "status": "ERROR",
            "length": 0,
            "content_type": "N/A",
            "content_hash": "",
            "error": str(e)
        }

async def run_auth_detection(urls, concurrency=10):
    semaphore = asyncio.Semaphore(concurrency)
    base_headers = {"User-Agent": "Mozilla/5.0 (compatible; AuthWallDetector/1.0)"}
    auth_headers = {
        **base_headers,
        "Authorization": "Bearer fake-token-12345",
        "Cookie": "session=fake-session-12345"
    }
    no_headers = {
        **base_headers,
        "Authorization": "",
        "Cookie": ""
    }

    results = []

    async def sem_fetch(url):
        async with semaphore:
            async with httpx.AsyncClient(timeout=10) as client:
                normal_resp = await fetch_url(url, base_headers, client)
                # Request using a fake auth token
                auth_resp = await fetch_url(url, auth_headers, client)
                #Request without auth headers
                no_auth_resp = await fetch_url(url, no_headers, client)

                return {
                    "url": url,
                    "normal": normal_resp,
                    "with_auth": auth_resp,
                    "without_auth": no_auth_resp
                }

    tasks = [sem_fetch(url) for url in urls]
    for f in asyncio.as_completed(tasks):
        result = await f
        results.append(result)

    return results

def analyze_auth_walls(results):
    findings = []
    for r in results:
        normal = r["normal"]
        with_auth = r["with_auth"]
        without_auth = r["without_auth"]

        if normal["status"] == "ERROR" or with_auth["status"] == "ERROR" or without_auth["status"] == "ERROR":
            continue
        # If normal and with_auth are identical, but without_auth differs, requires auth
        if (normal["status"] == with_auth["status"] and
            normal["content_hash"] == with_auth["content_hash"] and
            (without_auth["status"] != normal["status"] or
             without_auth["content_hash"] != normal["content_hash"])):
            findings.append({
                "type": "Requires authentication",
                "severity": "INFO",
                "url": r["url"],
                "info": f"Normal: {normal['status']}, Without auth: {without_auth['status']}"
            })
            #If normal and without_auth are identical, but with_auth differs... doesn't require auth
        elif (normal["status"] == without_auth["status"] and
              normal["content_hash"] == without_auth["content_hash"] and
              (with_auth["status"] != normal["status"] or
               with_auth["content_hash"] != normal["content_hash"])):
            findings.append({
                "type": "Does not require authentication",
                "severity": "HIGH",
                "url": r["url"],
                "info": f"Normal: {normal['status']}, With auth: {with_auth['status']}"
            })
            # Weird behavior without auth token
        elif without_auth["status"] in [500, 502, 503]:
            findings.append({
                "type": "Unusual behavior without auth",
                "severity": "MEDIUM",
                "url": r["url"],
                "info": f"Without auth: {without_auth['status']}"
            })

    return findings

def print_results_table(findings):
    if not findings:
        console.print("[green]No interesting finding detected.[/green]")
        return

    table = Table(title="···Authentication Findings···", show_header=True, header_style="bold cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="green")
    table.add_column("Info", style="yellow")
    table.add_column("URL", style="blue", overflow="fold")

    for f in findings:
        sev = f["severity"]
        color = "red" if sev == "CRITICAL" else "orange" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "blue"
        table.add_row(
            f["type"],
            f"[{color}]{sev}[/{color}]",
            f["info"],
            f["url"]
        )

    console.print(table)

def save_results(findings, output_dir="auth_wall_results"):
    import os
    import json
    os.makedirs(output_dir, exist_ok=True)  
    # Save findings
    with open(os.path.join(output_dir, "findings.json"), "w") as f:
        json.dump(findings, f, indent=2)
    #Persist findings based on severity
    from collections import defaultdict
    severities = defaultdict(list)
    for f in findings:
        severities[f["severity"]].append(f)

    for sev, items in severities.items():
        filename = os.path.join(output_dir, f"{sev.lower()}_findings.txt")
        with open(filename, "w") as f:
            for item in items:
                f.write(f"{item['url']} | {item['type']} | {item['info']}\n")

    console.print(f"Results saved to: {output_dir}/")

def print_summary(findings):
    total = len(findings)
    require_auth = len([f for f in findings if "🟢Requires authentication" in f["type"]])
    no_auth = len([f for f in findings if "🔵Does not require authentication" in f["type"]])
    weird = len([f for f in findings if "🟡Unusual behavior" in f["type"]])

    panel = Panel(
        f"""
🧨Summary:
  - Total findings analyzed: {total}
  - Endpoints requiring authentication: {require_auth}
  - Publicly accessible endpoints: {no_auth}
  - Endpoints with unusual behavior: {weird}
        """,
        title="⚡Auth Wall Detector - Access Control Recon",
        expand=False
    )
    console.print(panel)

def load_urls(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

async def main():
    parser = argparse.ArgumentParser(description="Detect endpoints that require authentication")
    parser.add_argument("-w", "--wordlist", required=True, help="Input file with URLs (one per line)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrency level")
    parser.add_argument("--output-dir", default="auth_wall_results", help="Output directory")
    args = parser.parse_args()

    urls = load_urls(args.wordlist)
    if not urls:
        console.print("[red]No valid URLs found.[/red]")
        return

    console.print(f"[blue]Analyzing {len(urls)} URLs...[/blue]")

    results = await run_auth_detection(urls, concurrency=args.concurrency)
    findings = analyze_auth_walls(results) 

    print_results_table(findings)
    print_summary(findings)
    save_results(findings, output_dir=args.output_dir) 

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
