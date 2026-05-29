import shutil
import subprocess


ASSETFINDER_TIMEOUT_SECONDS = 120


def run_assetfinder(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        return []

    if not shutil.which("assetfinder"):
        return []

    try:
        result = subprocess.run(
            ["assetfinder", "--subs-only", target.strip()],
            capture_output=True,
            text=True,
            timeout=ASSETFINDER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return []
    except Exception as exc:
        return []

    if result.returncode != 0:
        return []

    return result.stdout.strip()
