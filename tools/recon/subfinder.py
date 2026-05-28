import shutil
import subprocess

def run_subfinder(target, mode="single", use_all_sources=False):
    """
    Unified Subfinder runner.

    Args:
        target (str): domain or file path
        mode (str): "single" or "list"
        use_all_sources (bool): if True, adds -all flag
    """

    print(f"\n[+] Running subfinder ({mode}) for {target}...\n")

    if not shutil.which('subfinder'):
        print("[+] Subfinder is not installed or not in PATH.")
        print("[+] Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return []

    cmd = ["subfinder"]

    # mode selection
    if mode == "single":
        cmd += ["-d", target]
    elif mode == "list":
        cmd += ["-dL", target]
    else:
        print("[+] Invalid mode. Use 'single' or 'list'.")
        return []

    # optional flag
    if use_all_sources:
        cmd.append("-all")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[+] Subfinder error: {result.stderr.strip()}")
            return []

        subdomains = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        print(f"[+] Subfinder completed. Found {len(subdomains)} subdomains.")
        return subdomains

    except Exception as e:
        print(f"[+] Error: {e}")
        return []