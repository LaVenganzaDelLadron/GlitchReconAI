from core.executor import run_tool

def run_ffuf(target: str, wordlist: str = "") -> str:
    if wordlist:
        return run_tool("ffuf", target, wordlist)

    return run_tool("ffuf", target)