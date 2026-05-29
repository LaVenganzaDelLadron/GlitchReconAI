import json

from tools.recon.assetfinder import run_assetfinder
from tools.recon.gau import parse_gau_output, run_gau
from tools.recon.httpx import run_httpx
from tools.recon.subfinder import run_subfinder
from tools.recon.katana import parse_katana_output, run_katana_advanced
from tools.recon.waybackurls import run_waybackurls
from core.dashboard import get_dashboard
from ai.analyzer import (
    analyze_assetfinder_output,
    analyze_gau_output,
    analyze_katana_output,
    analyze_subfinder_output,
    analyze_waybackurls_output,
    analyze_httpx_output,
)


"""
Main agent for running subfinder and analyzing results with AI.
Single entry point for all modes.
"""

def subfinder_agent(target, mode="single", use_all_sources=False, dashboard=None):
    dashboard = dashboard or get_dashboard()
    dashboard.start()

    try:
        dashboard.log(f"[+] Running subfinder ({mode}) for {target}...")

        data = run_subfinder(
            target,
            mode=mode,
            use_all_sources=use_all_sources
        )

        if data:
            dashboard.log(f"[+] Subfinder completed. Found {len(data)} subdomains.")
            dashboard.log(f"[+] Sending subfinder output to Ollama for {target}...")
            analyze_subfinder_output("\n".join(data), dashboard=dashboard)
        else:
            dashboard.log(f"[-] No subfinder data to analyze for {target}.")
    finally:
        dashboard.stop()


def katana_agent(target, dashboard=None):
    dashboard = dashboard or get_dashboard()
    dashboard.start()

    try:
        dashboard.log(f"[+] Running katana for {target}...")

        data = run_katana_advanced(target)
        raw_output = data.get("raw_output", "")

        if raw_output.startswith("[katana error]"):
            dashboard.log(raw_output)
            return

        parsed = parse_katana_output(raw_output)
        analysis_payload = {
            "target": data.get("target", target),
            "raw_output": raw_output,
            "endpoints": data.get("endpoints", []),
            "js_files": data.get("js_files", []),
            "possible_apis": data.get("possible_apis", []),
            "interesting_paths": parsed.get("interesting_paths", []),
        }

        dashboard.log("[+] Katana crawl completed.")
        dashboard.log(f"[+] URLs discovered: {len(analysis_payload['endpoints'])}")
        dashboard.log(f"[+] JavaScript files: {len(analysis_payload['js_files'])}")
        dashboard.log(f"[+] Possible APIs: {len(analysis_payload['possible_apis'])}")
        dashboard.log(f"[+] Interesting paths: {len(analysis_payload['interesting_paths'])}")

        if raw_output:
            dashboard.log(f"[+] Sending katana output to Ollama for {target}...")
            analyze_katana_output(json.dumps(analysis_payload, indent=2), dashboard=dashboard)
        else:
            dashboard.log(f"[-] No katana data to analyze for {target}.")
    finally:
        dashboard.stop()

def waybackurls_agent(target, dashboard=None):
    dashboard = dashboard or get_dashboard()
    dashboard.start()

    try:
        dashboard.log(f"[+] Running waybackurls for {target}...")

        data = run_waybackurls(target)

        if "error" in data:
            dashboard.log(data["error"])
            return

        statistics = data.get("statistics", {})
        analysis_payload = {
            "target": data.get("target", target),
            "raw_output": data.get("raw_output", ""),
            "urls": data.get("urls", []),
            "api_urls": data.get("api_urls", []),
            "js_files": data.get("js_files", []),
            "parameter_urls": data.get("parameter_urls", []),
            "interesting_urls": data.get("interesting_urls", []),
            "graphql_urls": data.get("graphql_urls", []),
            "statistics": statistics,
        }

        dashboard.log("[+] waybackurls completed.")
        dashboard.log(f"[+] Total URLs: {statistics.get('total_urls', 0)}")
        dashboard.log(f"[+] API URLs: {statistics.get('api_count', 0)}")
        dashboard.log(f"[+] JavaScript files: {statistics.get('js_count', 0)}")
        dashboard.log(f"[+] Parameter URLs: {statistics.get('parameter_count', 0)}")
        dashboard.log(f"[+] Interesting URLs: {statistics.get('interesting_count', 0)}")
        dashboard.log(f"[+] GraphQL URLs: {len(analysis_payload['graphql_urls'])}")

        if analysis_payload["urls"]:
            dashboard.log(f"[+] Sending waybackurls output to Ollama for {target}...")
            analyze_waybackurls_output(json.dumps(analysis_payload, indent=2), dashboard=dashboard)
        else:
            dashboard.log(f"[-] No waybackurls data to analyze for {target}.")
    finally:
        dashboard.stop()

def httpx_agent(targets_file, dashboard=None):
    dashboard = dashboard or get_dashboard()
    dashboard.start()

    try:
        dashboard.log(f"[+] Running httpx for targets in {targets_file}...")

        data = run_httpx(targets_file)

        if data.startswith("[ERROR]"):
            dashboard.log(data)
            return

        dashboard.log(f"[+] Sending httpx output to Ollama for targets in {targets_file}...")
        analyze_httpx_output(data, dashboard=dashboard)
    finally:
        dashboard.stop()


def gau_agent(target, dashboard=None):
    dashboard = dashboard or get_dashboard()
    dashboard.start()

    try:
        dashboard.log(f"[+] Running gau for {target}...")

        raw_output = run_gau(target)

        if raw_output.startswith("[ERROR]"):
            dashboard.log(raw_output)
            return

        parsed = parse_gau_output(raw_output)
        high_score_urls = [
            item
            for item in parsed.get("scored_urls", [])
            if item.get("score", 0) >= 70
        ]
        analysis_payload = {
            "target": target,
            "raw_output": raw_output,
            "parsed": parsed,
            "high_score_urls": high_score_urls,
        }

        dashboard.log("[+] gau completed.")
        dashboard.log(f"[+] Total URLs: {parsed.get('total_urls', 0)}")
        dashboard.log(f"[+] API endpoints: {len(parsed.get('api_endpoints', []))}")
        dashboard.log(f"[+] JavaScript files: {len(parsed.get('js_files', []))}")
        dashboard.log(f"[+] Interesting paths: {len(parsed.get('interesting_paths', []))}")
        dashboard.log(f"[+] High-score URLs: {len(high_score_urls)}")

        if parsed.get("raw"):
            dashboard.log(f"[+] Sending gau output to Ollama for {target}...")
            analyze_gau_output(json.dumps(analysis_payload, indent=2), dashboard=dashboard)
        else:
            dashboard.log(f"[-] No gau data to analyze for {target}.")
    finally:
        dashboard.stop()


def assetfinder_agent(target, dashboard=None):
    dashboard = dashboard or get_dashboard()
    dashboard.start()

    try:
        dashboard.log(f"[+] Running assetfinder for {target}...")

        data = run_assetfinder(target)

        if data.startswith("[ERROR]"):
            dashboard.log(data)
            return

        subdomains = [line for line in data.splitlines() if line.strip()]
        dashboard.log(f"[+] Assetfinder completed. Found {len(subdomains)} subdomains.")
        dashboard.log(f"[+] Sending assetfinder output to Ollama for {target}...")
        analyze_assetfinder_output(data, dashboard=dashboard)
    finally:
        dashboard.stop()
