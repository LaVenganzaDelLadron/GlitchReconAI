# assetfinder.py
from core.executor import run_tool

def run_assetfinder(target: str) -> str:
    return run_tool("assetfinder", target)