from tools.recon.subfinder import run_subfinder
from ai.ollama_client import ask_ai

def scan_target(target):
    print(f"\n[+] Scanning target: {target}\n")
    
    subdomains = run_subfinder(target)
    
    if not subdomains:
        print("[+] No subdomains found or subfinder could not run. Skipping AI analysis.")
        return

    ai_response = ask_ai("\n".join(subdomains))

    print("\n[+] AI Analysis:")
    print(ai_response)
