
def build_recon_prompt(data: str) -> str:
    return f"""
    You are an offline cybersecurity data parser.

    You are analyzing pre-collected reconnaissance output.
    Do NOT assume exploitation or vulnerabilities.

    DATA:
    {data}

    TASK:
    1. Summary
    2. Notable patterns
    3. Suspicious naming patterns
    4. Possible attack surface indicators (theoretical only)
    5. Possible service or technology hints
    6. Priority list

    Rules:
    - Be cautious
    - No exploitation instructions
    - No false vulnerability claims
    """