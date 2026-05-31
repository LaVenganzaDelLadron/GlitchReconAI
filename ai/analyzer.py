from ai.ollama_client import generate_response
from ai.prompt_engine import (
    build_assetfinder_prompt,
    build_katana_prompt,
    build_subfinder_prompt, 
    build_waybackurls_prompt, 
    build_httpx_prompt, 
    build_gau_prompt,
    build_nikto_prompt,
)

def analyze_subfinder_output(subdomains: str, dashboard=None) -> str:
    """
        Main entry point for AI analysis.
    """

    prompt = build_subfinder_prompt(subdomains)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis


def analyze_katana_output(data: str, dashboard=None) -> str:
    """
        Analyze structured Katana crawl output with local AI.
    """

    prompt = build_katana_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_waybackurls_output(data: str, dashboard=None) -> str:
    """
        Analyze structured waybackurls crawl output with local AI.
    """
    
    prompt = build_waybackurls_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_httpx_output(data: str, dashboard=None) -> str:
    """
        Analyze structured httpx crawl output with local AI.
    """
    
    prompt = build_httpx_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_gau_output(data: str, dashboard=None) -> str:
    """
        Analyze structured gau crawl output with local AI.
    """
    
    prompt = build_gau_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_assetfinder_output(data: str, dashboard=None) -> str:
    """
        Analyze structured assetfinder crawl output with local AI.
    """
    
    prompt = build_assetfinder_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis

def analyze_nikto_output(data: str, dashboard=None) -> str:
    """
        Analyze structured nikto crawl output with local AI.
    """    
    prompt = build_nikto_prompt(data)
    analysis = generate_response(prompt, dashboard=dashboard)
    return analysis