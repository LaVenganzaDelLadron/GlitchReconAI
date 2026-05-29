
def build_subfinder_prompt(data: str) -> str:
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


def build_katana_prompt(data: str) -> str:
    return f"""
    You are an offline cybersecurity reconnaissance analyst.

    You are analyzing pre-collected Katana web crawler output.
    This data is for authorized passive reconnaissance only.
    Do NOT provide exploitation steps, payloads, vulnerability confirmation, or attack instructions.

    DATA:
    {data}

    TASK:
    1. Summary of discovered web surface
    2. Notable URL and endpoint patterns
    3. JavaScript files worth reviewing manually
    4. API-looking paths and possible application areas
    5. Interesting paths such as login, admin, upload, or graphql
    6. Safe follow-up review priorities

    Rules:
    - Be cautious
    - Treat findings as leads, not confirmed vulnerabilities
    - Suggest only passive review and inventory actions
    - Do not include exploit commands or payloads
    """

def build_waybackurls_prompt(data: str) -> str:
    return f"""
    You are an offline cybersecurity reconnaissance analyst.

    You are analyzing pre-collected waybackurls output.
    This data is for authorized passive reconnaissance only.
    Do NOT provide exploitation steps, payloads, vulnerability confirmation, or attack instructions.

    DATA:
    {data}

    TASK:
    1. Summary of discovered web surface
    2. Notable URL and endpoint patterns
    3. JavaScript files worth reviewing manually
    4. API-looking paths and possible application areas
    5. Interesting paths such as login, admin, upload, or graphql
    6. Safe follow-up review priorities

    Rules:
    - Be cautious
    - Treat findings as leads, not confirmed vulnerabilities
    - Suggest only passive review and inventory actions
    - Do not include exploit commands or payloads
    """

def build_httpx_prompt(data: str) -> str:
    return f"""
    You are an offline cybersecurity reconnaissance analyst.
    
    You are analyzing pre-collected httpx output.
    This data is for authorized passive reconnaissance only.
    Do NOT provide exploitation steps, payloads, vulnerability confirmation, or attack instructions.

    DATA:
    {data}

    TASK:
    1. Summary of discovered web surface
    2. Notable URL and endpoint patterns
    3. JavaScript files worth reviewing manually
    4. API-looking paths and possible application areas
    5. Interesting paths such as login, admin, upload, or graphql
    6. Safe follow-up review priorities

    Rules:
    - Be cautious
    - Treat findings as leads, not confirmed vulnerabilities
    - Suggest only passive review and inventory actions
    - Do not include exploit commands or payloads
    """

def build_gau_prompt(data: str) -> str:
    return f"""
    You are an offline cybersecurity reconnaissance analyst.
    You are analyzing pre-collected gau output.
    This data is for authorized passive reconnaissance only.
    Do NOT provide exploitation steps, payloads, vulnerability confirmation, or attack instructions.
    DATA:
    {data}

    TASK:
    1. Summary of discovered web surface
    2. Notable URL and endpoint patterns
    3. JavaScript files worth reviewing manually
    4. API-looking paths and possible application areas
    5. Interesting paths such as login, admin, upload, or graphql
    6. Safe follow-up review priorities 
    Rules:
    - Be cautious
    - Treat findings as leads, not confirmed vulnerabilities
    - Suggest only passive review and inventory actions
    - Do not include exploit commands or payloads
    """

def build_assetfinder_prompt(data: str) -> str:
    return f"""
    You are an offline cybersecurity reconnaissance analyst.

    You are analyzing pre-collected assetfinder output.
    This data is for authorized passive reconnaissance only.
    Do NOT provide exploitation steps, payloads, vulnerability confirmation, or attack instructions.

    DATA:
    {data}

    TASK:
    1. Summary of discovered subdomains
    2. Notable patterns in subdomain naming
    3. Possible service or technology hints from subdomains
    4. Subdomains that may indicate interesting attack surface (theoretical only)
    5. Safe follow-up review priorities

    Rules:
    - Be cautious
    - Treat findings as leads, not confirmed vulnerabilities
    - Suggest only passive review and inventory actions
    - Do not include exploit commands or payloads
    """