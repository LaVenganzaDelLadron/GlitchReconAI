from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse


API_MARKERS = (
    "://api.",
    ".api.",
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/rest/",
    "/graphql",
    "/gql",
    "graphql",
    "swagger",
    "openapi",
)
JS_MARKERS = (".js", ".mjs", ".jsx")
AUTH_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "signup",
    "register",
    "auth",
    "oauth",
    "sso",
    "token",
    "jwt",
    "session",
    "password",
    "passwd",
    "reset",
    "forgot",
    "verify",
    "mfa",
    "2fa",
    "otp",
)
ADMIN_KEYWORDS = (
    "admin",
    "administrator",
    "dashboard",
    "panel",
    "manage",
    "management",
    "console",
    "cpanel",
    "controlpanel",
    "backend",
    "staff",
    "moderator",
    "internal",
)
HTTPX_STATUS_PATTERN = re.compile(r"\[(\d{3})\]")
HTTPX_TITLE_PATTERN = re.compile(r"\[(?!\d{3}\])([^\]]+)\]")
NIKTO_METADATA_PREFIXES = (
    "target ip:",
    "target hostname:",
    "target port:",
    "start time:",
    "end time:",
    "nikto",
)
NIKTO_HEADER_KEYWORDS = (
    "header",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "strict-transport-security",
    "content-security-policy",
    "server:",
)
NIKTO_DISCLOSURE_KEYWORDS = (
    "outdated",
    "version",
    "server leaks",
    "server banner",
    "retrieved",
    "disclosure",
    "apache",
    "nginx",
    "iis",
    "php",
    "openssl",
)
NIKTO_EXPOSURE_KEYWORDS = (
    "admin",
    "administrator",
    "login",
    "auth",
    "password",
    "passwd",
    "config",
    "configuration",
    "backup",
    ".bak",
    ".old",
    ".env",
    ".git",
    "directory indexing",
    "directory listing",
    "robots.txt",
    "phpinfo",
    "test page",
)


def parse_subdomains(raw: Any) -> dict[str, Any]:
    """
    Parse line-oriented subdomain output into a structured dictionary.
    """
    subdomains = _deduplicate(
        item.lower()
        for item in _iter_values(raw)
        if _looks_like_hostname(item)
    )

    return {
        "count": len(subdomains),
        "subdomains": subdomains,
    }


def parse_httpx(raw: Any) -> dict[str, Any]:
    """
    Parse httpx output into live-host and URL classification data.
    """
    entries: list[dict[str, Any]] = []
    urls: list[str] = []

    for line in _iter_values(raw):
        url = _extract_url(line)
        if not url:
            continue

        if url in urls:
            continue

        urls.append(url)
        entries.append(
            {
                "url": url,
                "host": _host_from_url(url),
                "status_code": _extract_status_code(line),
                "title": _extract_title(line),
                "raw": line,
            }
        )

    classified = _classify_urls(urls)

    return {
        "count": len(entries),
        "live_hosts": entries,
        "urls": urls,
        "hosts": _deduplicate(entry["host"] for entry in entries if entry["host"]),
        "apis": classified["apis"],
        "js_files": classified["js_files"],
        "auth_paths": classified["auth_paths"],
        "admin_paths": classified["admin_paths"],
        "statistics": {
            "live_host_count": len(entries),
            "api_count": len(classified["apis"]),
            "js_file_count": len(classified["js_files"]),
            "auth_path_count": len(classified["auth_paths"]),
            "admin_path_count": len(classified["admin_paths"]),
        },
    }


def parse_katana(raw: Any) -> dict[str, Any]:
    """
    Parse Katana crawler output into endpoint and classification data.
    """
    urls = _deduplicate(
        url
        for item in _iter_values(raw)
        if (url := _extract_url(item))
    )
    classified = _classify_urls(urls)

    return {
        "count": len(urls),
        "urls": urls,
        "endpoints": urls,
        "apis": classified["apis"],
        "js_files": classified["js_files"],
        "auth_paths": classified["auth_paths"],
        "admin_paths": classified["admin_paths"],
        "statistics": {
            "url_count": len(urls),
            "api_count": len(classified["apis"]),
            "js_file_count": len(classified["js_files"]),
            "auth_path_count": len(classified["auth_paths"]),
            "admin_path_count": len(classified["admin_paths"]),
        },
    }


def parse_gau(raw: Any) -> dict[str, Any]:
    """
    Parse gau output into URL inventory and classification data.
    """
    urls = _deduplicate(
        url
        for item in _iter_values(raw)
        if (url := _extract_url(item))
    )
    classified = _classify_urls(urls)

    return {
        "count": len(urls),
        "urls": urls,
        "apis": classified["apis"],
        "js_files": classified["js_files"],
        "auth_paths": classified["auth_paths"],
        "admin_paths": classified["admin_paths"],
        "statistics": {
            "url_count": len(urls),
            "api_count": len(classified["apis"]),
            "js_file_count": len(classified["js_files"]),
            "auth_path_count": len(classified["auth_paths"]),
            "admin_path_count": len(classified["admin_paths"]),
        },
    }


def parse_nikto(raw: Any) -> dict[str, Any]:
    """
    Parse Nikto output into structured scanner findings.
    """
    lines = list(_iter_values(raw))
    findings: list[str] = []
    interesting_headers: list[str] = []
    disclosure_hints: list[str] = []
    exposure_findings: list[str] = []
    target: dict[str, str] = {
        "host": "",
        "ip": "",
        "port": "",
    }

    for line in lines:
        cleaned = _clean_nikto_line(line)
        if not cleaned:
            continue

        _update_nikto_target(target, cleaned)

        if not _is_nikto_finding(cleaned):
            continue

        findings.append(cleaned)
        lowered = cleaned.lower()

        if any(keyword in lowered for keyword in NIKTO_HEADER_KEYWORDS):
            interesting_headers.append(cleaned)

        if any(keyword in lowered for keyword in NIKTO_DISCLOSURE_KEYWORDS):
            disclosure_hints.append(cleaned)

        if any(keyword in lowered for keyword in NIKTO_EXPOSURE_KEYWORDS):
            exposure_findings.append(cleaned)

    findings = _deduplicate(findings)
    interesting_headers = _deduplicate(interesting_headers)
    disclosure_hints = _deduplicate(disclosure_hints)
    exposure_findings = _deduplicate(exposure_findings)

    return {
        "target": target,
        "count": len(findings),
        "findings": findings,
        "interesting_headers": interesting_headers,
        "outdated_or_disclosure_hints": disclosure_hints,
        "exposure_findings": exposure_findings,
        "statistics": {
            "finding_count": len(findings),
            "interesting_header_count": len(interesting_headers),
            "outdated_or_disclosure_count": len(disclosure_hints),
            "exposure_count": len(exposure_findings),
        },
    }


def _classify_urls(urls: Iterable[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {
        "apis": [],
        "js_files": [],
        "auth_paths": [],
        "admin_paths": [],
    }

    for url in urls:
        lowered = url.lower()

        if any(marker in lowered for marker in API_MARKERS):
            result["apis"].append(url)

        if _is_javascript_url(lowered):
            result["js_files"].append(url)

        if any(keyword in lowered for keyword in AUTH_KEYWORDS):
            result["auth_paths"].append(url)

        if any(keyword in lowered for keyword in ADMIN_KEYWORDS):
            result["admin_paths"].append(url)

    return {
        key: _deduplicate(values)
        for key, values in result.items()
    }


def _clean_nikto_line(line: str) -> str:
    cleaned = line.strip()
    if cleaned.startswith("+"):
        cleaned = cleaned[1:].strip()
    elif cleaned.startswith("- "):
        cleaned = cleaned[2:].strip()
    return cleaned


def _is_nikto_finding(line: str) -> bool:
    lowered = line.lower()
    if lowered.startswith(NIKTO_METADATA_PREFIXES):
        return False

    return bool(line and not set(line) <= {"-", "="})


def _update_nikto_target(target: dict[str, str], line: str) -> None:
    lowered = line.lower()

    if lowered.startswith("target hostname:"):
        target["host"] = line.split(":", 1)[1].strip()
    elif lowered.startswith("target ip:"):
        target["ip"] = line.split(":", 1)[1].strip()
    elif lowered.startswith("target port:"):
        target["port"] = line.split(":", 1)[1].strip()


def _iter_values(raw: Any) -> Iterable[str]:
    if raw is None:
        return []

    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return []

        parsed_json = _try_parse_json(stripped)
        if parsed_json is not None:
            return _iter_values(parsed_json)

        return [line.strip() for line in stripped.splitlines() if line.strip()]

    if isinstance(raw, dict):
        values: list[str] = []
        for value in raw.values():
            values.extend(_iter_values(value))
        return values

    if isinstance(raw, Iterable) and not isinstance(raw, (bytes, bytearray)):
        values = []
        for item in raw:
            if isinstance(item, str):
                cleaned = item.strip()
                if cleaned:
                    values.append(cleaned)
            else:
                values.extend(_iter_values(item))
        return values

    return [str(raw).strip()] if str(raw).strip() else []


def _try_parse_json(value: str) -> Any | None:
    if not value.startswith(("{", "[")):
        return None

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _extract_url(value: str) -> str:
    for token in value.split():
        cleaned = token.strip(" ,;\"'")
        if cleaned.startswith(("http://", "https://")):
            return cleaned

    if value.startswith(("http://", "https://")):
        return value.strip()

    return ""


def _extract_status_code(value: str) -> int | None:
    match = HTTPX_STATUS_PATTERN.search(value)
    if not match:
        return None

    return int(match.group(1))


def _extract_title(value: str) -> str:
    for match in HTTPX_TITLE_PATTERN.finditer(value):
        candidate = match.group(1).strip()
        if candidate and not candidate.lower().startswith(("http://", "https://")):
            return candidate

    return ""


def _host_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


def _looks_like_hostname(value: str) -> bool:
    if not value or " " in value:
        return False

    candidate = value.strip().lower()
    if candidate.startswith(("http://", "https://")):
        candidate = _host_from_url(candidate)

    if not candidate or "." not in candidate:
        return False

    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    return all(character in allowed for character in candidate)


def _is_javascript_url(lowered_url: str) -> bool:
    parsed = urlparse(lowered_url)
    path = parsed.path or lowered_url
    return any(path.endswith(marker) or f"{marker}?" in lowered_url for marker in JS_MARKERS)


def _deduplicate(items: Iterable[str]) -> list[str]:
    unique_items: list[str] = []
    seen: set[str] = set()

    for item in items:
        cleaned = item.strip() if isinstance(item, str) else str(item).strip()
        if not cleaned or cleaned in seen:
            continue

        unique_items.append(cleaned)
        seen.add(cleaned)

    return unique_items
