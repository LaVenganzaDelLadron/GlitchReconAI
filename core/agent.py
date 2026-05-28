from tools.recon.subfinder import sub_finder
from ai.ollama_client import ask_ai

def scan_target(target):
    print(f"Scanning target: {target}")
    
    # Step 1: Find subdomains
    subdomains = sub_finder(target)
    print(f"Found subdomains: {subdomains}")
    
    # Step 2: Analyze each subdomain with AI
    for subdomain in subdomains:
        print(f"Analyzing subdomain: {subdomain}")
        analysis_result = ask_ai(subdomain)
        print(f"Analysis result for {subdomain}: {analysis_result}")