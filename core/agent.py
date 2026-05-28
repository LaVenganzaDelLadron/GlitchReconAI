from tools.recon.subfinder import run_subfinder
from ai.analyzer import analyze_subdomains


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
        analysis = analyze_subdomains("\n".join(data))
        print(f"Analysis for {target}:\n{analysis}")
    else:
        print(f"No data to analyze for {target}.")