from ai.prompt_engine import build_katana_prompt, build_subfinder_prompt, build_waybackurls_prompt
from ai.ollama_client import generate_response

def analyze_subfinder_output(subdomains: str) -> str:
    """
        Main entry point for AI analysis.
    """

    prompt = build_subfinder_prompt(subdomains)
    analysis = generate_response(prompt)
    return analysis


def analyze_katana_output(data: str) -> str:
    """
        Analyze structured Katana crawl output with local AI.
    """

    prompt = build_katana_prompt(data)
    analysis = generate_response(prompt)
    return analysis

def analyze_waybackurls_output(data: str) -> str:
    """
        Analyze structured waybackurls crawl output with local AI.
    """
    
    prompt = build_waybackurls_prompt(data)
    analysis = generate_response(prompt)
    return analysis