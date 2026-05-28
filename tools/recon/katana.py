import shutil
import subprocess
from typing import Dict, List


KATANA_TIMEOUT_SECONDS = 120
INTERESTING_PATH_KEYWORDS = ("login", "admin", "upload", "graphql")


def run_katana(target: str, depth: int = 4, js_crawl: bool = True) -> str:
    """
    Run Katana against an authorized target and return raw crawler output.

    This wrapper only performs passive crawling/reconnaissance through Katana.
    It returns readable error strings instead of raising so downstream AI/ML
    pipeline stages can handle failures cleanly.
    """
    validation_error = _validate_target(target)
    if validation_error:
        return validation_error

    if not isinstance(depth, int) or depth < 1:
        return "[katana error] depth must be a positive integer."

    if not shutil.which("katana"):
        return "[katana error] katana is not installed or not in PATH."

    cmd = ["katana", "-u", target.strip(), "-d", str(depth), "-silent"]
    if js_crawl:
        cmd.append("-jc")

    return _run_katana_command(cmd)


def run_katana_advanced(target: str) -> Dict[str, object]:
    """
    Run Katana with richer passive reconnaissance flags and parsed output.
    """
    result = {
        "target": target.strip() if isinstance(target, str) else "",
        "raw_output": "",
        "endpoints": [],
        "js_files": [],
        "possible_apis": [],
    }

    validation_error = _validate_target(target)
    if validation_error:
        result["raw_output"] = validation_error
        return result

    if not shutil.which("katana"):
        result["raw_output"] = "[katana error] katana is not installed or not in PATH."
        return result

    cmd = [
        "katana",
        "-u",
        target.strip(),
        "-d",
        "5",
        "-jc",
        "-td",
        "-kf",
        "all",
        "-silent",
    ]

    raw_output = _run_katana_command(cmd)
    result["raw_output"] = raw_output

    if raw_output.startswith("[katana error]"):
        return result

    parsed = parse_katana_output(raw_output)
    result["endpoints"] = parsed["urls"]
    result["js_files"] = parsed["js_files"]
    result["possible_apis"] = parsed["endpoints"]

    return result


def parse_katana_output(raw: str) -> Dict[str, List[str]]:
    """
    Parse line-oriented Katana output into structured recon artifacts.
    """
    parsed = {
        "urls": [],
        "endpoints": [],
        "js_files": [],
        "interesting_paths": [],
    }

    if not raw:
        return parsed

    for line in raw.splitlines():
        item = line.strip()
        if not item:
            continue

        lowered = item.lower()

        if _looks_like_url(item):
            _append_unique(parsed["urls"], item)

        if "/api/" in lowered:
            _append_unique(parsed["endpoints"], item)

        if ".js" in lowered:
            _append_unique(parsed["js_files"], item)

        if any(keyword in lowered for keyword in INTERESTING_PATH_KEYWORDS):
            _append_unique(parsed["interesting_paths"], item)

    return parsed


def _run_katana_command(cmd: List[str]) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=KATANA_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return f"[katana error] command timed out after {KATANA_TIMEOUT_SECONDS} seconds."
    except Exception as exc:
        return f"[katana error] unexpected failure: {exc}"

    if result.returncode != 0:
        error_detail = result.stderr.strip() or "katana exited with a non-zero status."
        return f"[katana error] {error_detail}"

    return result.stdout.strip()


def _validate_target(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        return "[katana error] target must be a non-empty string."

    return ""


def _looks_like_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def _append_unique(items: List[str], value: str) -> None:
    if value not in items:
        items.append(value)
