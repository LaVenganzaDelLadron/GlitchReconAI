from pathlib import Path


PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts"

PROMPT_FILES = {
    "subfinder": PROMPT_DIR / "recon_prompts" / "subfinder_prompt.txt",
    "assetfinder": PROMPT_DIR / "recon_prompts" / "assetfinder_prompt.txt",
    "httpx": PROMPT_DIR / "recon_prompts" / "httpx_prompt.txt",
    "katana": PROMPT_DIR / "recon_prompts" / "katana_prompt.txt",
    "gau": PROMPT_DIR / "recon_prompts" / "gau_prompt.txt",
    "waybackurls": PROMPT_DIR / "recon_prompts" / "waybackurls_prompt.txt",
    "nikto": PROMPT_DIR / "scan_prompts" / "nikto_prompt.txt",
    "ffuf": PROMPT_DIR / "scan_prompts" / "ffuf_prompt.txt",
    "nuclei": PROMPT_DIR / "scan_prompts" / "nuclei_prompt.txt",
    "nmap": PROMPT_DIR / "scan_prompts" / "nmap_prompt.txt",
}


def build_prompt(tool_name: str, data: str) -> str:
    template_path = PROMPT_FILES.get(tool_name)

    if template_path is None:
        raise ValueError(f"Unsupported prompt tool: {tool_name}")

    try:
        template = template_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Prompt file not found: {template_path}") from exc

    if "{data}" not in template:
        raise ValueError(f"Prompt file must include {{data}} placeholder: {template_path}")

    return template.format(data=data)


def build_subfinder_prompt(data: str) -> str:
    return build_prompt("subfinder", data)


def build_assetfinder_prompt(data: str) -> str:
    return build_prompt("assetfinder", data)


def build_httpx_prompt(data: str) -> str:
    return build_prompt("httpx", data)


def build_katana_prompt(data: str) -> str:
    return build_prompt("katana", data)


def build_gau_prompt(data: str) -> str:
    return build_prompt("gau", data)


def build_waybackurls_prompt(data: str) -> str:
    return build_prompt("waybackurls", data)


def build_nikto_prompt(data: str) -> str:
    return build_prompt("nikto", data)


def build_ffuf_prompt(data: str) -> str:
    return build_prompt("ffuf", data)


def build_nuclei_prompt(data: str) -> str:
    return build_prompt("nuclei", data)


def build_nmap_prompt(data: str) -> str:
    return build_prompt("nmap", data)
