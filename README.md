# GlitchReconAI

GlitchReconAI is a CLI reconnaissance automation tool for authorized security research workflows. It supports Subfinder subdomain discovery and Katana passive web crawling, then sends collected output to a local Ollama model for structured analysis and safe review suggestions.

This project is intended for analyzing collected reconnaissance output. It does not perform exploitation.

## Features

- Interactive command-line menu.
- Subfinder support for:
  - single target domains
  - target list files
  - all-sources mode
- Katana support for passive web crawling:
  - URL discovery
  - JavaScript crawling
  - technology detection
  - known-file discovery
- Structured Katana parsing for:
  - URLs
  - JavaScript files
  - API-like paths
  - interesting paths such as login, admin, upload, and graphql
- Local AI analysis through Ollama.
- Structured subdomain and crawl-output analysis.
- Modular project layout for future recon, intelligence, scanning, web, reporting, and ML features.

## Requirements

- Python 3
- `requests` Python package
- `figlet` and `lolcat` for banner output
- `subfinder` installed and available in your `PATH`
- `katana` installed and available in your `PATH`
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

Install Katana:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
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
    [1] Subfinder
      [1] Single Target
      [2] List of Targets
      [3] All Sources
    [2] Katana
      Enter authorized target URL/domain
```

For Subfinder single-target or all-sources mode, enter a domain such as:

```text
example.com
```

For Subfinder list mode, enter the path to a file containing target domains.

For Katana mode, enter an authorized target URL or domain such as:

```text
https://example.com
```

## Current Project Flow

- `glitch.py` starts the app.
- `view/start.py` handles the main menu and module selection.
- `view/recon.py` lets the user choose Subfinder or Katana and collects target input.
- `core/agent.py` runs the selected recon tool and sends results for AI analysis.
- `tools/recon/subfinder.py` wraps the Subfinder command.
- `tools/recon/katana.py` wraps Katana, captures crawler output, and parses URLs, JavaScript files, API-like paths, and interesting paths.
- `ai/prompt_engine.py` builds Subfinder and Katana analysis prompts.
- `ai/ollama_client.py` sends prompts to local Ollama.
- `ai/analyzer.py` connects the prompt builder and Ollama client.

## AI Analysis

GlitchReconAI sends collected recon output to a local Ollama model and asks for structured inventory-style analysis. The current recommended model is:

```text
qwen2.5:7b
```

Subfinder output is analyzed as subdomain inventory. Katana output is analyzed as passive crawl data, including discovered URLs, JavaScript files, API-looking paths, and interesting paths.

AI suggestions are intended as leads for manual review only. They should not be treated as proof of vulnerabilities.

## Notes

- Only use this tool against domains you own or are authorized to assess.
- The AI output is based on text patterns only and should not be treated as proof of vulnerabilities.
- Katana support is limited to passive crawling and output parsing.
- GlitchReconAI does not include exploitation logic, vulnerability confirmation, payload generation, or active attack behavior.
- Some folders and modules are placeholders for future expansion.
- Current implemented recon flow includes Subfinder and Katana.

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

### `katana is not installed or not in PATH`

Install Katana and make sure your Go binary directory is available:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
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
