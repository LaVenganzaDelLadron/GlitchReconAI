from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


PENDING_STATUS = "pending"
HTTPX_PRIORITY = 90
KATANA_PRIORITY = 80
JS_ANALYSIS_PRIORITY = 70


@dataclass(frozen=True)
class PlanItem:
    action: str
    tool: str
    targets: list[str]
    reason: str
    priority: int
    status: str = PENDING_STATUS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def create_plan(results: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Create a deterministic next-step reconnaissance plan from parsed results.
    """
    if not isinstance(results, dict):
        return []

    plan: list[PlanItem] = []

    subdomains = _extract_subdomains(results)
    if subdomains:
        plan.append(
            PlanItem(
                action="run_httpx",
                tool="httpx",
                targets=subdomains,
                reason="Subdomains were discovered and should be probed for live HTTP services.",
                priority=HTTPX_PRIORITY,
            )
        )

    live_hosts = _extract_live_hosts(results)
    if live_hosts:
        plan.append(
            PlanItem(
                action="run_katana",
                tool="katana",
                targets=live_hosts,
                reason="Live hosts were discovered and should be crawled for routes, endpoints, and JavaScript files.",
                priority=KATANA_PRIORITY,
            )
        )

    js_files = _extract_list(results, "js_files")
    if js_files:
        plan.append(
            PlanItem(
                action="run_js_analysis",
                tool="js_analysis",
                targets=js_files,
                reason="JavaScript files were discovered and should be reviewed for endpoints, secrets, and application paths.",
                priority=JS_ANALYSIS_PRIORITY,
            )
        )

    return [
        item.to_dict()
        for item in sorted(plan, key=lambda item: item.priority, reverse=True)
    ]


def next_action(plan: list[dict[str, Any]]) -> dict[str, Any] | None:
    """
    Return the highest-priority pending action from a structured plan.
    """
    if not isinstance(plan, list):
        return None

    pending_actions = [
        item
        for item in plan
        if isinstance(item, dict) and item.get("status", PENDING_STATUS) == PENDING_STATUS
    ]
    if not pending_actions:
        return None

    return max(
        pending_actions,
        key=lambda item: _safe_int(item.get("priority"), default=0),
    )


def prioritize_targets(results: dict[str, Any]) -> list[str]:
    """
    Return targets ordered by recon value while preserving first-seen order.
    """
    if not isinstance(results, dict):
        return []

    prioritized_groups = [
        _extract_list(results, "apis"),
        _extract_list(results, "auth_paths"),
        _extract_list(results, "admin_paths"),
        _extract_list(results, "js_files"),
        _extract_live_hosts(results),
        _extract_subdomains(results),
    ]

    return _deduplicate(
        target
        for group in prioritized_groups
        for target in group
    )


def _extract_subdomains(results: dict[str, Any]) -> list[str]:
    subdomains = _extract_list(results, "subdomains")
    if subdomains:
        return subdomains

    if _safe_int(results.get("count"), default=0) > 0:
        return _extract_list(results, "hosts")

    return []


def _extract_live_hosts(results: dict[str, Any]) -> list[str]:
    live_hosts = results.get("live_hosts", [])
    extracted = _extract_targets(live_hosts)
    if extracted:
        return extracted

    statistics = results.get("statistics", {})
    live_count = 0
    if isinstance(statistics, dict):
        live_count = _safe_int(statistics.get("live_host_count"), default=0)

    if live_count > 0:
        return _extract_list(results, "urls") or _extract_list(results, "hosts")

    return []


def _extract_list(results: dict[str, Any], key: str) -> list[str]:
    return _extract_targets(results.get(key, []))


def _extract_targets(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [value.strip()] if value.strip() else []

    if isinstance(value, dict):
        for key in ("url", "host", "target", "domain", "subdomain"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return [item.strip()]
        return []

    if isinstance(value, (list, tuple, set)):
        targets: list[str] = []
        for item in value:
            targets.extend(_extract_targets(item))
        return _deduplicate(targets)

    return []


def _deduplicate(items: Any) -> list[str]:
    unique_items: list[str] = []
    seen: set[str] = set()

    for item in items:
        if not isinstance(item, str):
            continue

        cleaned = item.strip()
        if not cleaned or cleaned in seen:
            continue

        unique_items.append(cleaned)
        seen.add(cleaned)

    return unique_items


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default

    try:
        return int(value)
    except (TypeError, ValueError):
        return default
