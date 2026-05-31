# gau.py
from core.executor import run_tool
from core.parser import parse_gau


def run_gau(target: str) -> str:
    return run_tool("gau", target)


def parse_gau_output(raw: str) -> dict:
    parsed = parse_gau(raw)
    interesting_paths = _deduplicate(
        parsed["apis"] + parsed["auth_paths"] + parsed["admin_paths"]
    )

    return {
        "total_urls": parsed["count"],
        "api_endpoints": parsed["apis"],
        "js_files": parsed["js_files"],
        "interesting_paths": interesting_paths,
        "raw": parsed["urls"],
        "auth_related": parsed["auth_paths"],
        "admin_panels": parsed["admin_paths"],
        "sensitive_files": [],
        "dev_environments": [],
        "file_exposures": [],
        "scored_urls": [],
    }


def _deduplicate(items: list[str]) -> list[str]:
    unique_items = []
    seen = set()

    for item in items:
        if item in seen:
            continue

        unique_items.append(item)
        seen.add(item)

    return unique_items
