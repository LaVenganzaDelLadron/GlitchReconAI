from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MEMORY_DIR = Path("memory")
MEMORY_EXTENSION = ".json"
MEMORY_ID_PATTERN = re.compile(r"[^a-zA-Z0-9_.-]+")


def save_memory(
    content: dict[str, Any] | str,
    memory_id: str | None = None,
    **metadata: Any,
) -> dict[str, Any]:
    """
    Save or update a long-term project memory entry.
    """
    if not isinstance(content, (dict, str)):
        raise ValueError("content must be a dictionary or string.")

    now = _utc_now()
    resolved_memory_id = _sanitize_memory_id(memory_id) if memory_id else _new_memory_id(now)
    memory_path = _memory_path(resolved_memory_id)

    existing_memory: dict[str, Any] = {}
    if memory_path.exists():
        existing_memory = _read_json(memory_path)

    original_timestamp = existing_memory.get("timestamp") or now
    existing_metadata = existing_memory.get("metadata", {})
    if not isinstance(existing_metadata, dict):
        existing_metadata = {}

    memory = {
        "memory_id": resolved_memory_id,
        "timestamp": original_timestamp,
        "updated_at": now,
        "content": _json_safe(content),
        "metadata": _json_safe({**existing_metadata, **metadata}),
    }

    _write_json(memory_path, memory)
    return memory


def load_memory(memory_id: str) -> dict[str, Any]:
    """
    Load a memory entry by bare id or JSON filename.
    """
    memory_path = _memory_path(memory_id)
    if not memory_path.exists():
        raise FileNotFoundError(f"Memory entry not found: {memory_id}")

    return _read_json(memory_path)


def search_memory(query: str) -> list[dict[str, Any]]:
    """
    Search memory entries case-insensitively across id, content, metadata, and timestamps.
    """
    if not isinstance(query, str) or not query.strip():
        return []

    if not MEMORY_DIR.exists():
        return []

    normalized_query = query.strip().lower()
    matches: list[dict[str, Any]] = []

    for memory_path in MEMORY_DIR.glob(f"*{MEMORY_EXTENSION}"):
        try:
            memory = _read_json(memory_path)
        except (json.JSONDecodeError, OSError, ValueError):
            continue

        searchable_text = _searchable_text(memory)
        if normalized_query not in searchable_text:
            continue

        matches.append(
            {
                "memory_id": memory.get("memory_id", memory_path.stem),
                "timestamp": memory.get("timestamp", ""),
                "updated_at": memory.get("updated_at", ""),
                "content": memory.get("content"),
                "metadata": memory.get("metadata", {}),
                "path": str(memory_path),
            }
        )

    return sorted(
        matches,
        key=lambda item: item.get("updated_at") or item.get("timestamp") or "",
        reverse=True,
    )


def _new_memory_id(timestamp: str) -> str:
    safe_timestamp = timestamp.replace("+00:00", "Z")
    safe_timestamp = re.sub(r"[^0-9TZ]", "", safe_timestamp)
    return _sanitize_memory_id(f"memory_{safe_timestamp}")


def _sanitize_memory_id(memory_id: str | None) -> str:
    if not isinstance(memory_id, str) or not memory_id.strip():
        raise ValueError("memory_id must be a non-empty string.")

    name = memory_id.strip()
    if name.endswith(MEMORY_EXTENSION):
        name = name[: -len(MEMORY_EXTENSION)]

    name = name.replace("/", "_").replace("\\", "_")
    name = MEMORY_ID_PATTERN.sub("_", name)
    name = name.strip("._-")

    if not name:
        raise ValueError("memory_id must contain at least one safe character.")

    return name


def _memory_path(memory_id: str) -> Path:
    safe_memory_id = _sanitize_memory_id(memory_id)
    memory_path = MEMORY_DIR / f"{safe_memory_id}{MEMORY_EXTENSION}"

    base = MEMORY_DIR.resolve()
    resolved_path = memory_path.resolve()
    if base not in resolved_path.parents and resolved_path != base:
        raise ValueError("Resolved memory path is outside the memory directory.")

    return memory_path


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as memory_file:
        data = json.load(memory_file)

    if not isinstance(data, dict):
        raise ValueError(f"Memory file must contain a JSON object: {path}")

    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as memory_file:
        json.dump(data, memory_file, indent=2, sort_keys=True, ensure_ascii=False)
        memory_file.write("\n")


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


def _searchable_text(memory: dict[str, Any]) -> str:
    values = {
        "memory_id": memory.get("memory_id", ""),
        "timestamp": memory.get("timestamp", ""),
        "updated_at": memory.get("updated_at", ""),
        "content": memory.get("content", ""),
        "metadata": memory.get("metadata", {}),
    }
    return json.dumps(values, sort_keys=True, default=str).lower()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
