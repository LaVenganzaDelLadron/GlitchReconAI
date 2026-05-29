import subprocess
import shutil

def run_httpx(targets_file: str) -> str:
    """
    Runs httpx and returns raw output for AI processing
    """

    if not shutil.which("httpx"):
        return []

    try:
        result = subprocess.run(
            ["httpx", targets_file],
            capture_output=True,
            text=True
        )

        return result.stdout

    except Exception as e:
        return []