from tools.recon.gau import parse_gau_output


LEGACY_GAU_KEYS = {
    "total_urls",
    "api_endpoints",
    "js_files",
    "interesting_paths",
    "raw",
    "auth_related",
    "admin_panels",
    "sensitive_files",
    "dev_environments",
    "file_exposures",
    "scored_urls",
}


def test_parse_gau_output_preserves_legacy_shape():
    parsed = parse_gau_output("https://example.com/api/users")

    assert set(parsed) == LEGACY_GAU_KEYS


def test_parse_gau_output_delegates_shared_classification():
    raw = """
    https://example.com/api/users
    https://example.com/static/app.js
    https://example.com/login
    https://admin.example.com/dashboard
    not-a-url
    https://example.com/api/users
    """

    parsed = parse_gau_output(raw)

    assert parsed["total_urls"] == 4
    assert parsed["raw"] == [
        "https://example.com/api/users",
        "https://example.com/static/app.js",
        "https://example.com/login",
        "https://admin.example.com/dashboard",
    ]
    assert parsed["api_endpoints"] == ["https://example.com/api/users"]
    assert parsed["js_files"] == ["https://example.com/static/app.js"]
    assert parsed["auth_related"] == ["https://example.com/login"]
    assert parsed["admin_panels"] == ["https://admin.example.com/dashboard"]
    assert parsed["interesting_paths"] == [
        "https://example.com/api/users",
        "https://example.com/login",
        "https://admin.example.com/dashboard",
    ]


def test_parse_gau_output_empty_output_returns_legacy_empty_shape():
    parsed = parse_gau_output("")

    assert parsed == {
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
