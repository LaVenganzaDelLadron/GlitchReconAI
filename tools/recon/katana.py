import shutil
import subprocess
from typing import Dict, List


KATANA_TIMEOUT_SECONDS = 120
INTERESTING_PATH_KEYWORDS = (
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
        return []

    if not shutil.which("katana"):
        return []

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
        result["raw_output"] = []
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
        return []
    except Exception as exc:
        return []

    if result.returncode != 0:
        error_detail = result.stderr.strip() or "katana exited with a non-zero status."
        return []

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
