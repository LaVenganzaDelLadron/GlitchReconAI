# nikto.py
from core.executor import run_tool

NIKTO_TIMEOUT_SECONDS = 300


def run_nikto(target: str) -> str:
    return run_tool("nikto", target, options={"timeout": NIKTO_TIMEOUT_SECONDS})
