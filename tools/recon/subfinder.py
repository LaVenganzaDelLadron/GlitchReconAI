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

    if not shutil.which('subfinder'):
        return []

    cmd = ["subfinder"]

    # mode selection
    if mode == "single":
        cmd += ["-d", target]
    elif mode == "list":
        cmd += ["-dL", target]
    else:
        return []

    # optional flag
    if use_all_sources:
        cmd.append("-all")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return []

        subdomains = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        return subdomains

    except Exception as e:
        return []
