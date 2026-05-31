from core.executor import run_tool

NMAP_TIMEOUT_SECONDS = 400

def run_nmap(target: str) -> str:
    return run_tool("nmap", target, options={"timeout": NMAP_TIMEOUT_SECONDS})