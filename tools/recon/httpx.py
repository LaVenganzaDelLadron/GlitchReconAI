# httpx.py
from core.executor import run_tool

def run_httpx(target: str) -> str:
    return run_tool("httpx", target)