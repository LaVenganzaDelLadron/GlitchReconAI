from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ai.analyzer import (
    analyze_assetfinder_output,
    analyze_gau_output,
    analyze_httpx_output,
    analyze_katana_output,
    analyze_subfinder_output,
    analyze_waybackurls_output,
    analyze_nikto_output,
)
from core.dashboard import get_dashboard
from core.executor import run_tool
from core.logger import log_error, log_info, log_warning
from core.parser import parse_gau, parse_httpx, parse_katana, parse_subdomains, parse_nikto
from core.planner import create_plan
from core.reasoning import generate_reasoning
from core.session import save_session


Analyzer = Callable[[str], str]
Parser = Callable[[Any], dict[str, Any]]


def subfinder_agent(
    target: str,
    mode: str = "single",
    use_all_sources: bool = False,
    dashboard: Any = None,
) -> None:
    _run_recon_workflow(
        tool_name="subfinder",
        target=target,
        parser=parse_subdomains,
        analyzer=analyze_subfinder_output,
        dashboard=dashboard,
        tool_options={
            "mode": mode,
            "use_all_sources": use_all_sources,
        },
    )


def assetfinder_agent(target: str, dashboard: Any = None) -> None:
    _run_recon_workflow(
        tool_name="assetfinder",
        target=target,
        parser=parse_subdomains,
        analyzer=analyze_assetfinder_output,
        dashboard=dashboard,
    )


def httpx_agent(targets_file: str, dashboard: Any = None) -> None:
    _run_recon_workflow(
        tool_name="httpx",
        target=targets_file,
        parser=parse_httpx,
        analyzer=analyze_httpx_output,
        dashboard=dashboard,
    )


def katana_agent(target: str, dashboard: Any = None) -> None:
    _run_recon_workflow(
        tool_name="katana",
        target=target,
        parser=parse_katana,
        analyzer=analyze_katana_output,
        dashboard=dashboard,
    )


def waybackurls_agent(target: str, dashboard: Any = None) -> None:
    _run_recon_workflow(
        tool_name="waybackurls",
        target=target,
        parser=parse_gau,
        analyzer=analyze_waybackurls_output,
        dashboard=dashboard,
    )


def gau_agent(target: str, dashboard: Any = None) -> None:
    _run_recon_workflow(
        tool_name="gau",
        target=target,
        parser=parse_gau,
        analyzer=analyze_gau_output,
        dashboard=dashboard,
    )

def nikto_agent(target: str, dashboard: Any = None) -> None:
    _run_recon_workflow(
        tool_name="nikto",
        target=target,
        parser=parse_nikto,
        analyzer=analyze_nikto_output,
        dashboard=dashboard,
    )

def _run_recon_workflow(
    *,
    tool_name: str,
    target: str,
    parser: Parser,
    analyzer: Callable[..., str],
    dashboard: Any = None,
    tool_options: dict[str, Any] | None = None,
) -> None:
    dashboard = dashboard or get_dashboard()
    tool_label = _tool_label(tool_name)
    clean_target = _clean_target(target)
    tool_options = tool_options or {}

    dashboard.start()
    _set_target(dashboard, clean_target)
    _set_task(dashboard, f"Running {tool_label}")
    _set_status(dashboard, "Active")

    try:
        _log(dashboard, f"[+] Running {tool_label} for {clean_target}...")
        raw_output = run_tool(tool_name, clean_target, tool_options)

        if _is_error(raw_output):
            _log(dashboard, raw_output, level="error")
            _set_status(dashboard, "Error")
            return

        _log(dashboard, "[+] Parsing results...")
        parsed = parser(raw_output)

        _log_result_summary(dashboard, tool_name, parsed)

        _log(dashboard, "[+] Planning next actions...")
        plan = create_plan(parsed)

        _log(dashboard, "[+] Generating reasoning...")
        reasoning = generate_reasoning(parsed)

        result_document = {
            "target": clean_target,
            "tool": tool_name,
            "raw_output": raw_output,
            "parsed": parsed,
            "plan": plan,
            "reasoning": reasoning,
        }

        _log(dashboard, "[+] Saving session...")
        session = save_session(
            target=clean_target,
            results=result_document,
            tool=tool_name,
        )
        _log(dashboard, f"[+] Session saved: {session['session_id']}")

        payload = json.dumps(result_document, indent=2, sort_keys=True)
        _log(dashboard, "[+] Sending to Ollama...")
        analyzer(payload, dashboard=dashboard)

        _set_status(dashboard, "Ready")
        _set_task(dashboard, "Idle")
        _log(dashboard, f"[+] {tool_label} workflow completed.")
    except Exception as exc:
        message = f"[ERROR] {tool_label} workflow failed: {exc}"
        _log(dashboard, message, level="error")
        _set_status(dashboard, "Error")
    finally:
        dashboard.stop()


def _log_result_summary(
    dashboard: Any,
    tool_name: str,
    parsed: dict[str, Any],
) -> None:
    count = _safe_int(parsed.get("count"))
    statistics = parsed.get("statistics", {})

    if tool_name in {"subfinder", "assetfinder"}:
        _log(dashboard, f"[+] Subdomains discovered: {count}")
        return

    if tool_name == "httpx":
        live_count = count or _safe_int(_stat(statistics, "live_host_count"))
        _log(dashboard, f"[+] Live hosts discovered: {live_count}")
        _log(dashboard, f"[+] API-looking URLs: {len(parsed.get('apis', []))}")
        _log(dashboard, f"[+] JavaScript files: {len(parsed.get('js_files', []))}")
        return

    _log(dashboard, f"[+] URLs discovered: {count}")
    _log(dashboard, f"[+] API-looking URLs: {len(parsed.get('apis', []))}")
    _log(dashboard, f"[+] JavaScript files: {len(parsed.get('js_files', []))}")
    _log(dashboard, f"[+] Auth paths: {len(parsed.get('auth_paths', []))}")
    _log(dashboard, f"[+] Admin paths: {len(parsed.get('admin_paths', []))}")


def _stat(statistics: Any, key: str) -> Any:
    if isinstance(statistics, dict):
        return statistics.get(key)
    return None


def _log(dashboard: Any, message: str, level: str = "info") -> None:
    if level == "error":
        log_error(message)
    elif level == "warning":
        log_warning(message)
    else:
        log_info(message)

    dashboard.log(message)


def _set_target(dashboard: Any, target: str) -> None:
    setter = getattr(dashboard, "set_target", None)
    if callable(setter):
        setter(target)


def _set_task(dashboard: Any, task: str) -> None:
    setter = getattr(dashboard, "set_task", None)
    if callable(setter):
        setter(task)


def _set_status(dashboard: Any, status: str) -> None:
    setter = getattr(dashboard, "set_status", None)
    if callable(setter):
        setter(status)


def _is_error(output: Any) -> bool:
    return isinstance(output, str) and output.strip().startswith("[ERROR]")


def _clean_target(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string.")
    return target.strip()


def _tool_label(tool_name: str) -> str:
    labels = {
        "subfinder": "Subfinder",
        "assetfinder": "Assetfinder",
        "httpx": "Httpx",
        "katana": "Katana",
        "waybackurls": "Waybackurls",
        "gau": "GAU",
    }
    return labels.get(tool_name, tool_name)


def _safe_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
