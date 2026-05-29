import requests


def generate_response(prompt: str, dashboard=None) -> str:
    OLLAMA_URL = 'http://localhost:11434/api/generate'

    response = requests.post(
        OLLAMA_URL,
        json={
            'model': 'qwen2.5:7b',
            'prompt': prompt,
            'stream': False, # or False if you want to receive the response in one go
            }
        )
    ai_response = response.json()['response']

    if dashboard is not None:
        dashboard.ai_output(ai_response)

    return ai_response
