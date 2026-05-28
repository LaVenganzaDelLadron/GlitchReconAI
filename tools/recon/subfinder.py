import shutil
import subprocess
from pathlib import Path

def run_subfinder(target):
    print(f"\n[+] Running subfinder for {target}...\n")

    if not shutil.which('subfinder'):
        print("[+] Subfinder is not installed or is not available in your PATH.")
        print("[+] Install it with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("[+] Then make sure your Go bin directory is in PATH, for example: export PATH=$PATH:~/go/bin")
        return []


    try:
        result = subprocess.run(
            ['subfinder', '-d', target, '-o'],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            subdomains = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip()
            ]
            print(f"[+] Subfinder completed successfully. Found {len(subdomains)} subdomains.")
            return subdomains
        else:
            print(f"[+] Subfinder encountered an error: {result.stderr.strip()}")
            return []
    except FileNotFoundError:
        print("[+] Subfinder is not installed or is not available in your PATH.")
        return []
    except Exception as e:
        print(f"[+] An error occurred while running subfinder: {e}")
        return []
