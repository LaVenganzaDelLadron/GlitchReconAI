import requests

def generate_response(prompt: str) -> str:
    OLLAMA_URL = 'http://localhost:11434/api/generate'

    response = requests.post(
        OLLAMA_URL,
        json={
            'model': 'qwen2.5:7b',
            'prompt': prompt,
            'stream': False,
            }
        )
    return response.json()['response']
