from ai.prompt_engine import build_recon_prompt
from ai.ollama_client import generate_response

def analyze_subdomains(subdomains: str) -> str:
    """
        Main entry point for AI analysis.
    """

    prompt = build_recon_prompt(subdomains)
    analysis = generate_response(prompt)
    return analysis
