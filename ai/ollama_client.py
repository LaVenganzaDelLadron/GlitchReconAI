import requests

def ask_ai(data):
    prompt = f""" analyze this subdomain and give me the following information: {data}"""

    response = requests.post(
        'http://localhost:11434/api/ask', 
        json={
            'model': 'deepseek-coder:6.7b',
            'prompt': prompt,
            'stream': False
            }
        )
    return response.json()['response']