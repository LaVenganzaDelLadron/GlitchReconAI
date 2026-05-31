from core.executor import run_tool

def run_katana_advanced(target):
    raw = run_tool(
        "katana",
        target,
        {
            "depth": 5
        }
    )

    return {
        "target": target,
        "raw_output": raw
    }