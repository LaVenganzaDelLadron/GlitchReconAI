from unittest.mock import patch

from core.executor import run_command, run_parallel, run_tool
from core.parser import parse_nikto
from tools.scanning.nikto import NIKTO_TIMEOUT_SECONDS, run_nikto


def test_run_tool_rejects_empty_nikto_target():
    result = run_tool("nikto", "")

    assert result == "[ERROR] nikto requires a non-empty target."


def test_run_tool_builds_safe_nikto_command():
    with patch("core.executor.run_command", return_value="ok") as run_command_mock:
        result = run_tool("nikto", "https://example.com", options={"timeout": 45})

    assert result == "ok"
    run_command_mock.assert_called_once_with(
        ["nikto", "-h", "https://example.com"],
        timeout=45,
    )


def test_run_tool_builds_nmap_with_clean_positional_args():
    with patch("core.executor.run_command", return_value="ok") as run_command_mock:
        result = run_tool("nmap", "192.168.1.1")

    assert result == "ok"
    run_command_mock.assert_called_once_with(
        ["nmap", "-sV", "-sC", "-Pn", "-T4", "192.168.1.1"],
        timeout=300,
    )


def test_run_tool_accepts_keyword_options_without_positional_injection():
    with patch("core.executor.run_command", return_value="ok") as run_command_mock:
        result = run_tool("nmap", "192.168.1.1", timing=3, ports="80,443")

    assert result == "ok"
    run_command_mock.assert_called_once_with(
        ["nmap", "-sV", "-sC", "-Pn", "-T3", "-p", "80,443", "192.168.1.1"],
        timeout=300,
    )


def test_run_parallel_tool_task_uses_options_schema():
    task = {
        "tool": "nmap",
        "args": ["192.168.1.1"],
        "options": {"timing": 2, "ports": "22"},
    }

    with patch("core.executor.run_command", return_value="ok") as run_command_mock:
        result = run_parallel([task])

    assert result == ["ok"]
    run_command_mock.assert_called_once_with(
        ["nmap", "-sV", "-sC", "-Pn", "-T2", "-p", "22", "192.168.1.1"],
        timeout=300,
    )


def test_run_tool_rejects_dict_in_positional_args():
    result = run_tool("nmap", {"target": "192.168.1.1"}, "192.168.1.2")

    assert result == "[ERROR] Tool positional args must not include option dictionaries."


def test_run_nikto_delegates_to_shared_executor():
    with patch("tools.scanning.nikto.run_tool", return_value="raw nikto output") as run_tool_mock:
        result = run_nikto("https://example.com")

    assert result == "raw nikto output"
    run_tool_mock.assert_called_once_with(
        "nikto",
        "https://example.com",
        options={"timeout": NIKTO_TIMEOUT_SECONDS},
    )


def test_executor_reports_missing_command():
    result = run_command(["glitchreconai-command-that-should-not-exist"])

    assert result.startswith("[ERROR] Command not found:")


def test_run_tool_rejects_unsupported_tool():
    result = run_tool("not-a-real-tool", "example.com")

    assert result == "[ERROR] Unsupported tool: not-a-real-tool"


def test_parse_nikto_extracts_structured_findings():
    raw = """
    - Nikto v2.5.0
    + Target IP:          93.184.216.34
    + Target Hostname:    example.com
    + Target Port:        443
    + Server: Apache/2.4.49
    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-Content-Type-Options header is not set.
    + Apache/2.4.49 appears to be outdated.
    + /admin/: Admin login page found.
    + /config.bak: Backup configuration file may be exposed.
    + End Time: 2026-05-31 12:05:00
    """

    parsed = parse_nikto(raw)

    assert parsed["target"] == {
        "host": "example.com",
        "ip": "93.184.216.34",
        "port": "443",
    }
    assert parsed["count"] == 6
    assert "Server: Apache/2.4.49" in parsed["interesting_headers"]
    assert "Apache/2.4.49 appears to be outdated." in parsed["outdated_or_disclosure_hints"]
    assert "/admin/: Admin login page found." in parsed["exposure_findings"]
    assert "/config.bak: Backup configuration file may be exposed." in parsed["exposure_findings"]
    assert parsed["statistics"]["finding_count"] == 6
    assert parsed["statistics"]["interesting_header_count"] == 3
    assert parsed["statistics"]["outdated_or_disclosure_count"] == 2
    assert parsed["statistics"]["exposure_count"] == 2


def test_parse_nikto_empty_output():
    parsed = parse_nikto("")

    assert parsed == {
        "target": {
            "host": "",
            "ip": "",
            "port": "",
        },
        "count": 0,
        "findings": [],
        "interesting_headers": [],
        "outdated_or_disclosure_hints": [],
        "exposure_findings": [],
        "statistics": {
            "finding_count": 0,
            "interesting_header_count": 0,
            "outdated_or_disclosure_count": 0,
            "exposure_count": 0,
        },
    }
