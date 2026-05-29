from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Iterable, Sequence
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 300
KATANA_DEFAULT_DEPTH = 5
SUPPORTED_TOOLS = {
    "subfinder",
    "assetfinder",
    "httpx",
    "gau",
    "waybackurls",
    "katana",
}


def run_command(command: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS) -> str:
    """
    Execute a command and return stdout text.

    Failures are returned as readable error strings instead of exceptions so the
    dashboard and existing agent functions can display them directly.
    """
    if not command or not all(isinstance(part, str) and part for part in command):
        message = "[ERROR] Command must be a non-empty list of strings."
        _log_error(message)
        return message

    if not isinstance(timeout, int) or timeout <= 0:
        message = "[ERROR] Timeout must be a positive integer."
        _log_error(message)
        return message

    command_display = _format_command(command)
    _log_info(f"Executing command: {command_display}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        message = f"[ERROR] Command not found: {command[0]}"
        _log_error(message)
        return message
    except subprocess.TimeoutExpired as exc:
        stderr = _clean_text(exc.stderr)
        detail = f" Stderr: {stderr}" if stderr else ""
        message = (
            f"[ERROR] Command timed out after {timeout} seconds: "
            f"{command_display}.{detail}"
        )
        _log_error(message)
        return message
    except Exception as exc:
        message = f"[ERROR] Failed to execute command {command_display}: {exc}"
        _log_error(message)
        return message

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode != 0:
        detail = stderr or stdout or "No output returned."
        message = (
            f"[ERROR] Command failed with exit code {result.returncode}: "
            f"{command_display}. {detail}"
        )
        _log_error(message)
        return message

    if stderr:
        _log_warning(f"Command wrote to stderr: {command_display}. {stderr}")

    _log_info(f"Command completed successfully: {command_display}")
    return stdout


def run_tool(tool_name: str, *args: Any) -> str:
    """
    Build and run a supported recon tool command.

    Supported tools: subfinder, assetfinder, httpx, gau, waybackurls, katana.
    """
    normalized_name = _normalize_tool_name(tool_name)
    if normalized_name not in SUPPORTED_TOOLS:
        message = f"[ERROR] Unsupported tool: {tool_name}"
        _log_error(message)
        return message

    try:
        command, timeout = _build_tool_command(normalized_name, args)
    except ValueError as exc:
        message = f"[ERROR] {exc}"
        _log_error(message)
        return message

    return run_command(command, timeout=timeout)


def run_parallel(tasks: Iterable[Any]) -> list[str]:
    """
    Run tasks concurrently and return results in the same order as provided.

    Supported task forms:
    - callable
    - tuple/list: (callable, arg1, arg2, ...)
    - dict with {"tool": "subfinder", "args": ["example.com"]}
    - dict with {"command": ["python", "--version"], "timeout": 10}
    """
    task_list = list(tasks)
    if not task_list:
        return []

    results: list[str] = [""] * len(task_list)
    max_workers = min(32, len(task_list))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(_execute_task, task): index
            for index, task in enumerate(task_list)
        }

        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                message = f"[ERROR] Parallel task failed: {exc}"
                _log_error(message)
                results[index] = message

    return results


def _build_tool_command(tool_name: str, args: Sequence[Any]) -> tuple[list[str], int]:
    options = _extract_options(args)
    positional_args = _extract_positional_args(args)
    timeout = _get_timeout(options)

    if tool_name == "subfinder":
        target = _require_arg(tool_name, positional_args, 0, "target")
        mode = str(options.get("mode", "single")).lower()
        command = ["subfinder"]

        if mode in {"list", "file", "targets"}:
            command.extend(["-dL", target])
        elif mode == "single":
            command.extend(["-d", target])
        else:
            raise ValueError("subfinder mode must be 'single' or 'list'.")

        if bool(options.get("use_all_sources", options.get("all_sources", False))):
            command.append("-all")

        return command, timeout

    if tool_name == "assetfinder":
        target = _require_arg(tool_name, positional_args, 0, "target")
        return ["assetfinder", "--subs-only", target], timeout

    if tool_name == "httpx":
        targets_file = _require_arg(tool_name, positional_args, 0, "targets_file")
        return ["httpx", targets_file], timeout

    if tool_name == "gau":
        target = _require_arg(tool_name, positional_args, 0, "target")
        return ["gau", target], timeout

    if tool_name == "waybackurls":
        target = _require_arg(tool_name, positional_args, 0, "target")
        return ["waybackurls", target], timeout

    if tool_name == "katana":
        target = _require_arg(tool_name, positional_args, 0, "target")
        depth = _get_positive_int(options.get("depth", KATANA_DEFAULT_DEPTH), "depth")
        command = [
            "katana",
            "-u",
            target,
            "-d",
            str(depth),
            "-jc",
            "-td",
            "-kf",
            "all",
            "-silent",
        ]
        return command, timeout

    raise ValueError(f"Unsupported tool: {tool_name}")


def _execute_task(task: Any) -> str:
    if callable(task):
        return _stringify_result(task())

    if isinstance(task, dict):
        if "tool" in task:
            args = task.get("args", ())
            if args is None:
                args = ()
            if isinstance(args, (str, bytes)):
                args = (args,)
            if not isinstance(args, Iterable):
                args = (args,)
            kwargs = task.get("kwargs", {})
            if not isinstance(kwargs, dict):
                raise ValueError("Task 'kwargs' must be a dictionary.")
            return run_tool(str(task["tool"]), *tuple(args), kwargs)

        if "command" in task:
            command = task["command"]
            if not isinstance(command, list):
                raise ValueError("Task 'command' must be a list of strings.")
            timeout = task.get("timeout", DEFAULT_TIMEOUT_SECONDS)
            return run_command(command, timeout=_get_positive_int(timeout, "timeout"))

        raise ValueError("Task dictionary must include 'tool' or 'command'.")

    if isinstance(task, (tuple, list)) and task:
        runner = task[0]
        args = tuple(task[1:])

        if callable(runner):
            return _stringify_result(runner(*args))

        if isinstance(runner, str):
            return run_tool(runner, *args)

    raise ValueError(f"Unsupported task type: {type(task).__name__}")


def _extract_options(args: Sequence[Any]) -> dict[str, Any]:
    if args and isinstance(args[-1], dict):
        return dict(args[-1])
    return {}


def _extract_positional_args(args: Sequence[Any]) -> tuple[Any, ...]:
    if args and isinstance(args[-1], dict):
        return tuple(args[:-1])
    return tuple(args)


def _require_arg(
    tool_name: str,
    args: Sequence[Any],
    index: int,
    label: str,
) -> str:
    try:
        value = args[index]
    except IndexError as exc:
        raise ValueError(f"{tool_name} requires {label}.") from exc

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{tool_name} requires a non-empty {label}.")

    return value.strip()


def _get_timeout(options: dict[str, Any]) -> int:
    return _get_positive_int(options.get("timeout", DEFAULT_TIMEOUT_SECONDS), "timeout")


def _get_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a positive integer.")

    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a positive integer.") from exc

    if parsed <= 0:
        raise ValueError(f"{label} must be a positive integer.")

    return parsed


def _normalize_tool_name(tool_name: str) -> str:
    return str(tool_name).strip().lower().replace("_", "-")


def _format_command(command: Sequence[str]) -> str:
    return " ".join(command)


def _clean_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace").strip()
    if value is None:
        return ""
    return str(value).strip()


def _stringify_result(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _log_info(message: str) -> None:
    _call_logger("log_info", message)


def _log_warning(message: str) -> None:
    _call_logger("log_warning", message)


def _log_error(message: str) -> None:
    _call_logger("log_error", message)


def _call_logger(function_name: str, message: str) -> None:
    try:
        from core import logger

        log_function = getattr(logger, function_name, None)
        if callable(log_function):
            log_function(message)
    except Exception:
        return
