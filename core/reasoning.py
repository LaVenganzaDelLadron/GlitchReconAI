from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse


MAX_ITEMS_PER_SECTION = 10
API_SIGNALS = ("api", "graphql", "gql", "rest", "swagger", "openapi", "v1", "v2", "v3")
JS_SIGNALS = (".js", ".mjs", ".jsx")
AUTH_SIGNALS = (
    "auth",
    "login",
    "signin",
    "sign-in",
    "signup",
    "register",
    "oauth",
    "sso",
    "token",
    "jwt",
    "session",
    "password",
    "reset",
    "mfa",
    "2fa",
    "otp",
)
ADMIN_SIGNALS = (
    "admin",
    "administrator",
    "dashboard",
    "panel",
    "manage",
    "management",
    "console",
    "backend",
    "internal",
    "staff",
)
ENVIRONMENT_SIGNALS = (
    "dev",
    "staging",
    "stage",
    "test",
    "qa",
    "uat",
    "sandbox",
    "beta",
    "preprod",
    "demo",
)
INFRA_SIGNALS = ("cdn", "static", "assets", "media", "storage", "s3", "bucket")


def explain_finding(
    finding: str,
    category: str | None = None,
    context: dict[str, Any] | None = None,
) -> str:
    """
    Explain why a single reconnaissance finding may matter.
    """
    if not isinstance(finding, str) or not finding.strip():
        return "Finding: unavailable\nReasoning: No finding value was provided for analysis."

    clean_finding = finding.strip()
    inferred_category = _normalize_category(category) or _infer_category(clean_finding, context)
    signals = _detect_signals(clean_finding)

    lines = [f"Finding: {clean_finding}", f"Category: {_display_category(inferred_category)}"]

    if inferred_category == "api":
        lines.extend(
            [
                "Reasoning:",
                "- API-related assets often define service boundaries and application data flows.",
                "- This is useful for endpoint inventory, ownership mapping, and safe manual review.",
                "- Treat it as a prioritization signal, not as evidence of a vulnerability.",
            ]
        )
    elif inferred_category == "js_file":
        lines.extend(
            [
                "Reasoning:",
                "- JavaScript files can reveal client-side routes, API references, feature flags, and application structure.",
                "- Reviewing them helps identify endpoints that may not appear in simple crawling output.",
                "- Treat any interesting strings as leads for authorized validation only.",
            ]
        )
    elif inferred_category == "subdomain":
        lines.extend(
            [
                "Reasoning:",
                "- Subdomains expand the known attack surface and can indicate distinct services or environments.",
                "- Naming patterns may suggest ownership, purpose, or review priority.",
                "- Follow-up should focus on inventory and live-service validation.",
            ]
        )
    elif inferred_category == "auth_path":
        lines.extend(
            [
                "Reasoning:",
                "- Authentication-related paths are important for understanding access flows and session boundaries.",
                "- These paths deserve careful inventory because they often connect to user identity workflows.",
                "- This is a review priority signal, not a vulnerability claim.",
            ]
        )
    elif inferred_category == "admin_path":
        lines.extend(
            [
                "Reasoning:",
                "- Admin or management paths may represent privileged application surfaces.",
                "- They should be cataloged carefully and reviewed only within authorized scope.",
                "- Presence alone does not indicate exposure or weakness.",
            ]
        )
    else:
        lines.extend(
            [
                "Reasoning:",
                "- This item contributes to the reconnaissance inventory.",
                "- It may help correlate services, routes, or application components during later review.",
            ]
        )

    if signals:
        lines.append(f"Detected signals: {', '.join(signals)}")

    return "\n".join(lines)


def generate_reasoning(results: dict[str, Any]) -> str:
    """
    Generate a human-readable reasoning report for parsed reconnaissance results.
    """
    if not isinstance(results, dict) or not results:
        return "No findings available for reasoning."

    subdomains = _extract_values(results.get("subdomains"))
    apis = _extract_values(results.get("apis"))
    js_files = _extract_values(results.get("js_files"))
    auth_paths = _extract_values(results.get("auth_paths"))
    admin_paths = _extract_values(results.get("admin_paths"))
    live_hosts = _extract_values(results.get("live_hosts"))

    if not any((subdomains, apis, js_files, auth_paths, admin_paths, live_hosts)):
        return "No findings available for reasoning."

    lines = [
        "Reconnaissance Reasoning",
        "",
        "Summary:",
        f"- Subdomains: {len(subdomains)}",
        f"- Live hosts: {len(live_hosts)}",
        f"- APIs: {len(apis)}",
        f"- JavaScript files: {len(js_files)}",
        f"- Auth paths: {len(auth_paths)}",
        f"- Admin paths: {len(admin_paths)}",
    ]

    sections = [
        ("API Findings", apis, "api"),
        ("JavaScript Findings", js_files, "js_file"),
        ("Authentication Paths", auth_paths, "auth_path"),
        ("Admin Paths", admin_paths, "admin_path"),
        ("Subdomain Findings", subdomains, "subdomain"),
        ("Live Host Findings", live_hosts, "live_host"),
    ]

    for title, items, category in sections:
        rendered = _render_section(title, items, category)
        if rendered:
            lines.extend(["", rendered])

    follow_up = _build_follow_up_priorities(
        apis=apis,
        js_files=js_files,
        auth_paths=auth_paths,
        admin_paths=admin_paths,
        live_hosts=live_hosts,
        subdomains=subdomains,
    )
    if follow_up:
        lines.extend(["", "Safe Follow-up Priorities:"])
        lines.extend(f"- {item}" for item in follow_up)

    return "\n".join(lines).strip()


def _render_section(title: str, items: list[str], category: str) -> str:
    if not items:
        return ""

    lines = [f"{title}:"]
    for item in items[:MAX_ITEMS_PER_SECTION]:
        reason = _compact_reason(item, category)
        lines.append(f"- {item}: {reason}")

    remaining = len(items) - MAX_ITEMS_PER_SECTION
    if remaining > 0:
        lines.append(f"- ...and {remaining} more.")

    return "\n".join(lines)


def _compact_reason(finding: str, category: str) -> str:
    signals = _detect_signals(finding)
    signal_text = f" Signals: {', '.join(signals)}." if signals else ""

    if category == "api":
        return f"API-looking surface; useful for endpoint inventory and service-boundary review.{signal_text}"
    if category == "js_file":
        return f"Client-side asset; may reference routes, APIs, and application behavior.{signal_text}"
    if category == "auth_path":
        return f"Authentication-related path; useful for mapping identity and session workflows.{signal_text}"
    if category == "admin_path":
        return f"Management-looking path; should be cataloged as a privileged-surface lead.{signal_text}"
    if category == "subdomain":
        return f"Named host expands the known surface and may indicate service purpose or environment.{signal_text}"
    if category == "live_host":
        return f"Confirmed reachable web surface; good candidate for crawling and inventory.{signal_text}"

    return f"Reconnaissance inventory item for correlation and later review.{signal_text}"


def _build_follow_up_priorities(
    *,
    apis: list[str],
    js_files: list[str],
    auth_paths: list[str],
    admin_paths: list[str],
    live_hosts: list[str],
    subdomains: list[str],
) -> list[str]:
    priorities: list[str] = []

    if apis:
        priorities.append("Review API-looking assets for ownership, route inventory, and expected exposure.")
    if js_files:
        priorities.append("Review JavaScript files for referenced endpoints and application routes.")
    if auth_paths:
        priorities.append("Catalog authentication paths to understand identity and session-related flows.")
    if admin_paths:
        priorities.append("Catalog admin or management-looking paths within the authorized scope.")
    if live_hosts:
        priorities.append("Crawl live hosts to expand endpoint and JavaScript discovery.")
    if subdomains:
        priorities.append("Probe discovered subdomains to identify live services and reduce stale inventory.")

    return priorities


def _infer_category(finding: str, context: dict[str, Any] | None = None) -> str:
    lowered = finding.lower()

    if context:
        for key, category in (
            ("apis", "api"),
            ("js_files", "js_file"),
            ("auth_paths", "auth_path"),
            ("admin_paths", "admin_path"),
            ("subdomains", "subdomain"),
            ("live_hosts", "live_host"),
        ):
            if finding in _extract_values(context.get(key)):
                return category

    if _has_any(lowered, JS_SIGNALS):
        return "js_file"
    if _has_any(lowered, API_SIGNALS):
        return "api"
    if _has_any(lowered, AUTH_SIGNALS):
        return "auth_path"
    if _has_any(lowered, ADMIN_SIGNALS):
        return "admin_path"
    if _looks_like_hostname(finding):
        return "subdomain"
    if lowered.startswith(("http://", "https://")):
        return "live_host"

    return "unknown"


def _normalize_category(category: str | None) -> str:
    if not category:
        return ""

    normalized = category.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "api": "api",
        "apis": "api",
        "endpoint": "api",
        "endpoints": "api",
        "js": "js_file",
        "javascript": "js_file",
        "javascript_file": "js_file",
        "js_file": "js_file",
        "subdomain": "subdomain",
        "subdomains": "subdomain",
        "auth": "auth_path",
        "auth_path": "auth_path",
        "authentication": "auth_path",
        "admin": "admin_path",
        "admin_path": "admin_path",
        "live": "live_host",
        "live_host": "live_host",
        "host": "live_host",
    }
    return aliases.get(normalized, normalized)


def _display_category(category: str) -> str:
    labels = {
        "api": "API",
        "js_file": "JavaScript file",
        "subdomain": "Subdomain",
        "auth_path": "Authentication path",
        "admin_path": "Admin path",
        "live_host": "Live host",
        "unknown": "General finding",
    }
    return labels.get(category, category.replace("_", " ").title())


def _detect_signals(value: str) -> list[str]:
    lowered = value.lower()
    signals: list[str] = []

    signal_groups = (
        ("API keyword", API_SIGNALS),
        ("JavaScript file", JS_SIGNALS),
        ("Authentication keyword", AUTH_SIGNALS),
        ("Admin keyword", ADMIN_SIGNALS),
        ("Environment keyword", ENVIRONMENT_SIGNALS),
        ("Infrastructure keyword", INFRA_SIGNALS),
    )

    for label, keywords in signal_groups:
        if _has_any(lowered, keywords):
            signals.append(label)

    return signals


def _extract_values(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [value.strip()] if value.strip() else []

    if isinstance(value, dict):
        for key in ("url", "host", "target", "domain", "subdomain", "path"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return [item.strip()]

        values: list[str] = []
        for item in value.values():
            values.extend(_extract_values(item))
        return _deduplicate(values)

    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        values = []
        for item in value:
            values.extend(_extract_values(item))
        return _deduplicate(values)

    return []


def _deduplicate(items: Iterable[str]) -> list[str]:
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


def _looks_like_hostname(value: str) -> bool:
    candidate = value.strip().lower()
    if candidate.startswith(("http://", "https://")):
        parsed = urlparse(candidate)
        candidate = parsed.netloc

    if not candidate or "/" in candidate or "." not in candidate:
        return False

    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    return all(character in allowed for character in candidate)


def _has_any(value: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in value for keyword in keywords)
