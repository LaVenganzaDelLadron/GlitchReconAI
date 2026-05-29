import json

from tools.recon.subfinder import run_subfinder
from tools.recon.katana import parse_katana_output, run_katana_advanced
from tools.recon.waybackurls import run_waybackurls
from ai.analyzer import (
    analyze_katana_output,
    analyze_subfinder_output,
    analyze_waybackurls_output,
)


"""
Main agent for running subfinder and analyzing results with AI.
Single entry point for all modes.
"""

def subfinder_agent(target, mode="single", use_all_sources=False):
    print(f"Running subfinder ({mode}) for {target}...")

    data = run_subfinder(
        target,
        mode=mode,
        use_all_sources=use_all_sources
    )

    # Only analyze if we have data
    if data:
        print(f"Analyzing results for {target}...")
        analysis = analyze_subfinder_output("\n".join(data))
        print(f"Analysis for {target}:\n{analysis}")
    else:
        print(f"No data to analyze for {target}.")


def katana_agent(target):
    print(f"Running Katana for {target}...")

    data = run_katana_advanced(target)
    raw_output = data.get("raw_output", "")

    if raw_output.startswith("[katana error]"):
        print(raw_output)
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

    print("\n[+] Katana crawl completed.")
    print(f"[+] URLs discovered: {len(analysis_payload['endpoints'])}")
    print(f"[+] JavaScript files: {len(analysis_payload['js_files'])}")
    print(f"[+] Possible APIs: {len(analysis_payload['possible_apis'])}")
    print(f"[+] Interesting paths: {len(analysis_payload['interesting_paths'])}")

    if raw_output:
        print(f"\nAnalyzing Katana results for {target}...")
        analysis = analyze_katana_output(json.dumps(analysis_payload, indent=2))
        print(f"Katana analysis for {target}:\n{analysis}")
    else:
        print(f"No Katana data to analyze for {target}.")

def waybackurls_agent(target):
    print(f"Running waybackurls for {target}...")

    data = run_waybackurls(target)

    if "error" in data:
        print(data["error"])
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

    print("\n[+] waybackurls completed.")
    print(f"[+] Total URLs: {statistics.get('total_urls', 0)}")
    print(f"[+] API URLs: {statistics.get('api_count', 0)}")
    print(f"[+] JavaScript files: {statistics.get('js_count', 0)}")
    print(f"[+] Parameter URLs: {statistics.get('parameter_count', 0)}")
    print(f"[+] Interesting URLs: {statistics.get('interesting_count', 0)}")
    print(f"[+] GraphQL URLs: {len(analysis_payload['graphql_urls'])}")

    if analysis_payload["urls"]:
        print(f"\nAnalyzing waybackurls results for {target}...")
        analysis = analyze_waybackurls_output(json.dumps(analysis_payload, indent=2))
        print(f"waybackurls analysis for {target}:\n{analysis}")
    else:
        print(f"No waybackurls data to analyze for {target}.")
