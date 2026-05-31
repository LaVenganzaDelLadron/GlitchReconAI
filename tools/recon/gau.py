# gau.py
from core.executor import run_tool

def run_gau(target: str) -> str:
    return run_tool("gau", target)