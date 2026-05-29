from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SESSIONS_DIR = Path("sessions")
SESSION_EXTENSION = ".json"
SESSION_ID_PATTERN = re.compile(r"[^a-zA-Z0-9_.-]+")


def save_session(
    target: str,
    results: dict[str, Any],
    session_id: str | None = None,
    **metadata: Any,
) -> dict[str, Any]:
    """
    Save or update a reconnaissance session as JSON.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string.")

    if not isinstance(results, dict):
        raise ValueError("results must be a dictionary.")

    now = _utc_now()
    clean_target = target.strip()
    resolved_session_id = _sanitize_session_id(session_id) if session_id else _new_session_id(clean_target, now)
    session_path = _session_path(resolved_session_id)

    existing_session: dict[str, Any] = {}
    if session_path.exists():
        existing_session = _read_json(session_path)

    original_timestamp = existing_session.get("timestamp") or now
    existing_metadata = existing_session.get("metadata", {})
    if not isinstance(existing_metadata, dict):
        existing_metadata = {}

    session = {
        "session_id": resolved_session_id,
        "target": clean_target,
        "timestamp": original_timestamp,
        "updated_at": now,
        "results": _json_safe(results),
        "metadata": _json_safe({**existing_metadata, **metadata}),
    }

    _write_json(session_path, session)
    return session


def load_session(session_id: str) -> dict[str, Any]:
    """
    Load a session by bare session id or JSON filename.
    """
    session_path = _session_path(session_id)
    if not session_path.exists():
        raise FileNotFoundError(f"Session not found: {session_id}")

    return _read_json(session_path)


def list_sessions() -> list[dict[str, Any]]:
    """
    Return lightweight session summaries sorted by newest update first.
    """
    if not SESSIONS_DIR.exists():
        return []

    summaries: list[dict[str, Any]] = []
    for session_path in SESSIONS_DIR.glob(f"*{SESSION_EXTENSION}"):
        if session_path.name == "__init__.py":
            continue

        try:
            session = _read_json(session_path)
        except (json.JSONDecodeError, OSError, ValueError):
            continue

        summaries.append(
            {
                "session_id": session.get("session_id", session_path.stem),
                "target": session.get("target", ""),
                "timestamp": session.get("timestamp", ""),
                "updated_at": session.get("updated_at", ""),
                "path": str(session_path),
            }
        )

    return sorted(
        summaries,
        key=lambda item: item.get("updated_at") or item.get("timestamp") or "",
        reverse=True,
    )


def resume_session(session_id: str) -> dict[str, Any]:
    """
    Load a session and mark it as resumed in memory without rewriting the file.
    """
    session = load_session(session_id)
    session["resumed_at"] = _utc_now()
    return session


def _new_session_id(target: str, timestamp: str) -> str:
    safe_target = _sanitize_session_id(target).strip("._-") or "session"
    safe_timestamp = timestamp.replace("+00:00", "Z")
    safe_timestamp = re.sub(r"[^0-9TZ]", "", safe_timestamp)
    return _sanitize_session_id(f"{safe_target}_{safe_timestamp}")


def _sanitize_session_id(session_id: str | None) -> str:
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string.")

    name = session_id.strip()
    if name.endswith(SESSION_EXTENSION):
        name = name[: -len(SESSION_EXTENSION)]

    name = name.replace("/", "_").replace("\\", "_")
    name = SESSION_ID_PATTERN.sub("_", name)
    name = name.strip("._-")

    if not name:
        raise ValueError("session_id must contain at least one safe character.")

    return name


def _session_path(session_id: str) -> Path:
    safe_session_id = _sanitize_session_id(session_id)
    session_path = SESSIONS_DIR / f"{safe_session_id}{SESSION_EXTENSION}"

    base = SESSIONS_DIR.resolve()
    resolved_path = session_path.resolve()
    if base not in resolved_path.parents and resolved_path != base:
        raise ValueError("Resolved session path is outside the sessions directory.")

    return session_path


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as session_file:
        data = json.load(session_file)

    if not isinstance(data, dict):
        raise ValueError(f"Session file must contain a JSON object: {path}")

    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as session_file:
        json.dump(data, session_file, indent=2, sort_keys=True, ensure_ascii=False)
        session_file.write("\n")


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return _coerce_json_safe(value)


def _coerce_json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _coerce_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_coerce_json_safe(item) for item in value]

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return repr(value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
