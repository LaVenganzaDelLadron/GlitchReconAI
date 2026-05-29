import shutil
import subprocess
from typing import Dict, Iterable, List, Optional


WAYBACKURLS_TIMEOUT_SECONDS = 120
API_MARKERS = ("/api/", "/v1/", "/v2/")
INTERESTING_KEYWORDS = (
    "login", 
    "admin", 
    "upload", 
    "graphql",
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
    "forgot-password",
    "verify",
    "mfa",
    "2fa",
    "otp",
    "authenticate",
    "administrator",
    "dashboard",
    "panel",
    "manage",
    "management",
    "console",
    "cpanel",
    "controlpanel",
    "backend",
    "root",
    "superuser",
    "staff",
    "moderator",
    "api",
    "graphql",
    "gql",
    "rest",
    "swagger",
    "openapi",
    "v1",
    "v2",
    "v3",
    "internal-api",
    "public-api",
    "private-api",
    "dev",
    "staging",
    "stage",
    "test",
    "testing",
    "qa",
    "uat",
    "sandbox",
    "beta",
    "alpha",
    "demo",
    "preprod",
    "pre-prod",
    "local",
    "upload",
    "uploads",
    "file",
    "files",
    "download",
    "export",
    "import",
    "attachment",
    "media",
    "document",
    "archive",
    "backup",
    "dump",
    ".env",
    ".git",
    ".svn",
    ".htaccess",
    ".htpasswd",
    "config",
    "configuration",
    "settings",
    "secrets",
    "credentials",
    "private",
    "key",
    "pem",
    "backup",
    "bak",
    "old",
    "sql",
    "db",
    "database",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "member",
    "customer",
    "client",
    "employee",
    "staff",
    "payment",
    "payments",
    "billing",
    "invoice",
    "checkout",
    "cart",
    "order",
    "subscription",
    "paypal",
    "stripe",
    "wallet",
    "bank",
    "internal",
    "private",
    "vpn",
    "gateway",
    "proxy",
    "jenkins",
    "grafana",
    "kibana",
    "monitor",
    "metrics",
    "status",
    "health",
    "debug",
    "trace",
    "s3",
    "bucket",
    "storage",
    "cdn",
    "cloud",
    "blob",
    "firebase",
    "gcs",
    "azure",
    "mobile",
    "android",
    "ios",
    "app",
    "apk",
    ".php",
    ".aspx",
    ".jsp",
    ".json",
    ".xml",
    ".txt",
    ".bak",
    ".zip",
    ".tar",
    ".gz",
    ".sql",
    ".log",
    ".yml",
    ".yaml",
    ".env",
)

GRAPHQL_MARKERS = ("graphql", "gql")
PARAMETER_MARKERS = ("=", "?", "&")


def run_waybackurls(target: str) -> Dict[str, object]:
    """
    Run waybackurls for passive archived URL discovery.

    The returned dictionary is designed for downstream AI analysis, ML feature
    extraction, and attack surface graphing. This module only performs passive
    endpoint discovery and classification.
    """
    validation_error = _validate_target(target)
    if validation_error:
        return {"error": validation_error}

    if not shutil.which("waybackurls"):
        return {"error": "waybackurls is not installed or not in PATH."}

    target = target.strip()
    cmd = ["waybackurls", target]
    raw_output = _run_waybackurls_command(cmd)

    if raw_output.startswith("[waybackurls error]"):
        return {"error": raw_output}

    parsed = parse_waybackurls_output(raw_output)
    urls = parsed["urls"]
    api_urls = extract_api_urls(urls)
    js_files = extract_js_files(urls)
    parameter_urls = extract_parameter_urls(urls)
    interesting_urls = extract_interesting_urls(urls)
    graphql_urls = extract_graphql_urls(urls)

    return {
        "target": target,
        "raw_output": raw_output,
        "urls": urls,
        "api_urls": api_urls,
        "js_files": js_files,
        "parameter_urls": parameter_urls,
        "interesting_urls": interesting_urls,
        "graphql_urls": graphql_urls,
        "statistics": generate_statistics(
            urls=urls,
            api_urls=api_urls,
            js_files=js_files,
            parameter_urls=parameter_urls,
            interesting_urls=interesting_urls,
        ),
    }


def parse_waybackurls_output(raw: str) -> Dict[str, List[str]]:
    """
    Parse line-oriented waybackurls output and remove duplicate URLs.
    """
    if not raw:
        return {"urls": []}

    urls = [line.strip() for line in raw.splitlines() if line.strip()]
    return {"urls": _deduplicate(urls)}


def extract_api_urls(urls: List[str]) -> List[str]:
    """
    Extract URLs that look like API endpoints.
    """
    return _deduplicate(
        url for url in urls if any(marker in url.lower() for marker in API_MARKERS)
    )


def extract_js_files(urls: List[str]) -> List[str]:
    """
    Extract JavaScript file references.
    """
    return _deduplicate(url for url in urls if ".js" in url.lower())


def extract_parameter_urls(urls: List[str]) -> List[str]:
    """
    Extract URLs that contain query parameters or parameter-like markers.
    """
    return _deduplicate(
        url for url in urls if any(marker in url for marker in PARAMETER_MARKERS)
    )


def extract_interesting_urls(urls: List[str]) -> List[str]:
    """
    Extract URLs with words commonly useful for passive manual review.
    """
    return _deduplicate(
        url
        for url in urls
        if any(keyword in url.lower() for keyword in INTERESTING_KEYWORDS)
    )


def extract_graphql_urls(urls: List[str]) -> List[str]:
    """
    Extract URLs that reference GraphQL or GQL.
    """
    return _deduplicate(
        url for url in urls if any(marker in url.lower() for marker in GRAPHQL_MARKERS)
    )


def generate_statistics(
    urls: List[str],
    api_urls: List[str],
    js_files: List[str],
    parameter_urls: List[str],
    interesting_urls: List[str],
) -> Dict[str, int]:
    """
    Generate compact counts for dashboards, AI prompts, and ML features.
    """
    return {
        "total_urls": len(urls),
        "api_count": len(api_urls),
        "js_count": len(js_files),
        "parameter_count": len(parameter_urls),
        "interesting_count": len(interesting_urls),
    }


def _run_waybackurls_command(cmd: List[str]) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=WAYBACKURLS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return []
    except Exception as exc:
        return []

    if result.returncode != 0:
        error_detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or "waybackurls exited with a non-zero status."
        )
        return []

    return result.stdout.strip()


def _validate_target(target: Optional[str]) -> Optional[str]:
    if not isinstance(target, str) or not target.strip():
        return []

    return None


def _deduplicate(items: Iterable[str]) -> List[str]:
    """
    Remove duplicates while preserving discovery order.
    """
    unique_items = []
    seen = set()

    for item in items:
        if item not in seen:
            unique_items.append(item)
            seen.add(item)

    return unique_items

