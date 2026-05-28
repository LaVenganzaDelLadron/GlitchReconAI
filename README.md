# GlitchReconAI

GlitchReconAI is a CLI reconnaissance automation tool for authorized security research workflows. It currently focuses on running Subfinder, collecting subdomain results, and sending those results to a local Ollama model for structured text analysis.

This project is intended for analyzing collected reconnaissance output. It does not perform exploitation.

## Features

- Interactive command-line menu.
- Subfinder support for:
  - single target domains
  - target list files
  - all-sources mode
- Local AI analysis through Ollama.
- Structured subdomain pattern analysis.
- Modular project layout for future recon, intelligence, scanning, web, reporting, and ML features.

## Requirements

- Python 3
- `requests` Python package
- `figlet` and `lolcat` for banner output
- `subfinder` installed and available in your `PATH`
- Ollama running locally at `http://localhost:11434`
- Recommended Ollama model: `qwen2.5:7b`

## Installation

Clone or open the project, then install the Python dependency:

```bash
pip install requests
```

Install Subfinder:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:~/go/bin
```

Install and prepare the recommended Ollama model:

```bash
ollama pull qwen2.5:7b
```

Make sure Ollama is running before starting the tool.

## Usage

Run the app from the project root:

```bash
python3 glitch.py
```

Menu flow:

```text
[1] Create Project
  [1] Reconnaissance
    [1] Single Target
    [2] List of Targets
    [3] All Sources
```

For a single target or all-sources mode, enter a domain such as:

```text
example.com
```

For list mode, enter the path to a file containing target domains.

## Current Project Flow

- `glitch.py` starts the app.
- `view/start.py` handles the main menu and module selection.
- `view/recon.py` handles Subfinder mode selection and target input.
- `core/agent.py` runs Subfinder and sends results for AI analysis.
- `tools/recon/subfinder.py` wraps the Subfinder command.
- `ai/prompt_engine.py` builds the AI analysis prompt.
- `ai/ollama_client.py` sends prompts to local Ollama.
- `ai/analyzer.py` connects the prompt builder and Ollama client.

## AI Analysis

GlitchReconAI sends collected subdomains to a local Ollama model and asks for a structured inventory-style analysis. The current recommended model is:

```text
qwen2.5:7b
```

The analysis is designed to summarize naming patterns, unusual entries, possible service hints, and priority items for manual review.

## Notes

- Only use this tool against domains you own or are authorized to assess.
- The AI output is based on text patterns only and should not be treated as proof of vulnerabilities.
- Some folders and modules are placeholders for future expansion.
- Current implemented recon flow is centered on Subfinder.

## Troubleshooting

### `ModuleNotFoundError`

Run the app from the project root:

```bash
python3 glitch.py
```

### `subfinder is not installed or not in PATH`

Install Subfinder and make sure your Go binary directory is available:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:~/go/bin
```

### Ollama connection errors

Confirm Ollama is running and the model is installed:

```bash
ollama list
ollama pull qwen2.5:7b
```

### AI refusal or weak output

Use `qwen2.5:7b` and keep prompts focused on inventory analysis of static text data.

## Disclaimer

GlitchReconAI is for authorized security research, asset inventory, and defensive analysis. Do not use it against systems without permission.
