# waybackurls.py
from core.executor import run_tool

def run_waybackurls(target: str) -> str:
    return run_tool("waybackurls", target)