import shutil
import subprocess


GAU_TIMEOUT_SECONDS = 120


def run_gau(target: str) -> str:
    """
    Run gau for passive URL discovery and return raw stdout.
    """
    if not isinstance(target, str) or not target.strip():
        return "[ERROR] Invalid target provided."

    if not shutil.which("gau"):
        return "[ERROR] gau not installed or not in PATH."

    try:
        result = subprocess.run(
            ["gau", target.strip()],
            capture_output=True,
            text=True,
            timeout=GAU_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return f"[ERROR] gau command timed out after {GAU_TIMEOUT_SECONDS} seconds."
    except Exception as exc:
        return f"[ERROR] {exc}"

    if result.returncode != 0:
        error_detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or "gau exited with a non-zero status."
        )
        return f"[ERROR] {error_detail}"

    return result.stdout.strip()


def parse_gau_output(raw: str) -> dict:
    """
    Convert raw GAU output into structured passive recon data for AI + ML.
    """

    result = {
        "total_urls": 0,
        "api_endpoints": [],
        "js_files": [],
        "interesting_paths": [],
        "raw": [],
        "auth_related": [],
        "admin_panels": [],
        "sensitive_files": [],
        "dev_environments": [],
        "file_exposures": [],
        "scored_urls": [],
    }

    if not raw:
        return result

    auth_keywords = (
        "login",
        "signin",
        "signup",
        "register",
        "auth",
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
    admin_keywords = (
        "admin",
        "administrator",
        "dashboard",
        "panel",
        "manage",
        "console",
        "backend",
        "internal",
    )
    sensitive_markers = (
        ".env",
        ".git",
        ".svn",
        ".htaccess",
        ".htpasswd",
        "config",
        "secrets",
        "credentials",
        "key",
        "pem",
    )
    dev_keywords = (
        "dev",
        "staging",
        "stage",
        "test",
        "qa",
        "uat",
        "sandbox",
        "beta",
        "alpha",
        "demo",
        "preprod",
        "local",
    )
    api_markers = (
        "/api/",
        "/v1/",
        "/v2/",
        "/v3/",
        "graphql",
        "gql",
        "rest",
        "swagger",
        "openapi",
    )
    file_exposure_markers = (
        ".bak",
        ".backup",
        ".sql",
        ".zip",
        ".tar",
        ".gz",
        ".log",
        ".yml",
        ".yaml",
        ".json",
        ".xml",
        ".txt",
    )

    seen_urls = set()

    for line in raw.splitlines():
        url = line.strip()
        if not url:
            continue

        lower_url = url.lower()
        if not (lower_url.startswith("http://") or lower_url.startswith("https://")):
            continue

        if url in seen_urls:
            continue

        seen_urls.add(url)
        result["raw"].append(url)

        is_auth = any(keyword in lower_url for keyword in auth_keywords)
        is_admin = any(keyword in lower_url for keyword in admin_keywords)
        is_sensitive = any(marker in lower_url for marker in sensitive_markers)
        is_dev = any(keyword in lower_url for keyword in dev_keywords)
        is_api = any(marker in lower_url for marker in api_markers)
        is_file_exposure = any(marker in lower_url for marker in file_exposure_markers)
        is_js = ".js" in lower_url
        is_interesting = (
            is_auth
            or is_admin
            or is_sensitive
            or is_dev
            or is_api
            or is_file_exposure
        )

        if is_api:
            result["api_endpoints"].append(url)

        if is_js:
            result["js_files"].append(url)

        if is_interesting:
            result["interesting_paths"].append(url)

        if is_auth:
            result["auth_related"].append(url)

        if is_admin:
            result["admin_panels"].append(url)

        if is_sensitive:
            result["sensitive_files"].append(url)

        if is_dev:
            result["dev_environments"].append(url)

        if is_file_exposure:
            result["file_exposures"].append(url)

        score = 0
        if is_auth or is_admin:
            score += 30
        if is_api:
            score += 20
        if is_sensitive or is_file_exposure:
            score += 40
        if is_dev:
            score += 20

        result["scored_urls"].append(
            {
                "url": url,
                "score": min(score, 100),
            }
        )

    result["total_urls"] = len(result["raw"])
    return result
