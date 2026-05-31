from ai.ollama_client import generate_response
from ai.prompt_engine import (
    build_assetfinder_prompt,
    build_katana_prompt,
    build_nmap_prompt,
    build_nuclei_prompt,
    build_subfinder_prompt, 
    build_waybackurls_prompt, 
    build_httpx_prompt, 
    build_gau_prompt,
    build_nikto_prompt,
)

def analyze_subfinder_output(subdomains: str, dashboard=None) -> str:
    prompt = build_subfinder_prompt(subdomains)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_katana_output(data: str, dashboard=None) -> str:
    prompt = build_katana_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_waybackurls_output(data: str, dashboard=None) -> str:
    prompt = build_waybackurls_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_httpx_output(data: str, dashboard=None) -> str:
    prompt = build_httpx_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_gau_output(data: str, dashboard=None) -> str:
    prompt = build_gau_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_assetfinder_output(data: str, dashboard=None) -> str:
    prompt = build_assetfinder_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_nikto_output(data: str, dashboard=None) -> str:
    prompt = build_nikto_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_ffuf_output(data: str, dashboard=None) -> str:
    prompt = build_nikto_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_nuclei_output(data: str, dashboard=None) -> str:
    prompt = build_nuclei_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_nmap_output(data: str, dashboard=None) -> str:
    prompt = build_nmap_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis
