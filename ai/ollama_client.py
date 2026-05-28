import requests

def ask_ai(data):
    prompt = f"""
You are an offline cybersecurity data parser.

You are analyzing pre-collected raw reconnaissance output from tools like subfinder.
You are not performing hacking, exploitation, live scanning, or connecting to any system.
Treat the input as static text data only.

Your task is to:
- summarize the dataset
- identify notable subdomain naming patterns
- highlight suspicious or unusual naming patterns
- describe possible technology or service hints
- prioritize findings based only on structure and naming patterns

Use cautious language. Do not claim that a host is vulnerable based only on its name.

Data:
{data}

Respond only with this structured analysis format:
1. Summary
2. Notable patterns
3. Suspicious naming patterns
4. Possible attack surface indicators (theoretical only)
5. Priority list
    """

    response = requests.post(
        'http://localhost:11434/api/generate', 
        json={
            'model': 'deepseek-coder:6.7b',
            'prompt': prompt,
            'stream': False,
            }
        )
    return response.json()['response']
