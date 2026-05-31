# nikto.py
from core.executor import run_tool

def run_nikto(target: str) -> str:
    return run_tool("nikto", target)