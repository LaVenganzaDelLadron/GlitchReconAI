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

The recon tools are lightweight. The heavy part is local AI analysis through Ollama, especially on laptops with limited RAM or unsupported AMD Radeon GPU acceleration.

### Minimum: CLI recon only

- Python 3
- 4GB RAM
- `requests` Python package
- `figlet` and `lolcat` for banner output
- Internet access for passive recon tool queries
- `subfinder`, `katana`, and `waybackurls` installed as needed and available in your `PATH`

### Minimum: CLI + local AI

- 8GB RAM
- 4-core CPU
- Ollama running locally at `http://localhost:11434`
- Smaller Ollama model such as `qwen2.5:1.5b` or `qwen2.5:3b`
- SSD storage with several GB free for downloaded models

### Recommended: smooth local AI

- 16GB RAM or more
- 6GB to 8GB VRAM for 7B-class models when GPU acceleration works
- SSD storage with several GB free for models and cache files
- Recommended model for better analysis quality: `qwen2.5:7b`

`qwen2.5:7b` is about 4.7GB as an Ollama model download and may need substantially more memory while running. It can be too heavy for low-end laptops, especially if Ollama falls back to CPU.

### AMD Radeon notes

- AMD acceleration depends on your exact GPU model, operating system, driver, and Ollama backend support.
- On Linux, Ollama AMD GPU acceleration depends on compatible ROCm support and drivers.
- On Windows, AMD support may require the AMD ROCm Ollama build.
- Unsupported AMD Radeon GPUs may fall back to CPU, which can be slow or unstable on low-RAM laptops.
- If Ollama crashes, freezes, or makes the laptop unusable, use a smaller model first.

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

Install and prepare an Ollama model.

For low-resource laptops, start small:

```bash
ollama pull qwen2.5:1.5b
```

For a better balance of quality and memory use:

```bash
ollama pull qwen2.5:3b
```

For stronger analysis on machines with enough RAM or working GPU acceleration:

```bash
ollama pull qwen2.5:7b
```

Make sure Ollama is running before starting the tool. The current code uses the model configured in `ai/ollama_client.py`, currently `qwen2.5:7b`. If your laptop crashes or freezes, install a smaller model and change that value to `qwen2.5:1.5b` or `qwen2.5:3b`.

## Low-resource laptop setup

If your laptop has only 8GB RAM or an AMD Radeon GPU that Ollama does not accelerate correctly:

- Start with `qwen2.5:1.5b`.
- Try `qwen2.5:3b` if the smaller model is stable.
- Avoid `qwen2.5:7b` until you confirm your system has enough free RAM or working GPU acceleration.
- Close browsers, IDEs, virtual machines, and other heavy apps before AI analysis.
- Run recon collection first, then run AI analysis after you have the output.
- If Ollama falls back to CPU, expect slower responses and higher system memory pressure.

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

### Ollama crashes or freezes

This usually means the model is too heavy for the available RAM/VRAM, or GPU acceleration is not working.

Try a smaller model:

```bash
ollama pull qwen2.5:1.5b
ollama pull qwen2.5:3b
```

Then update the model name in `ai/ollama_client.py`.

### AMD GPU is not detected

AMD Radeon support depends on the exact GPU, operating system, Ollama build, and driver stack.

- On Linux, check ROCm compatibility and driver installation.
- On Windows, use the Ollama build that supports AMD ROCm if your GPU is supported.
- If the GPU is unsupported, Ollama may fall back to CPU.

### Laptop has only 8GB RAM

Use `qwen2.5:1.5b` first. If it runs reliably, try `qwen2.5:3b`. Avoid `qwen2.5:7b` unless the system remains stable.

### Use a smaller model

The model is configured in `ai/ollama_client.py`:

```python
'model': 'qwen2.5:7b',
```

For weaker hardware, change it to:

```python
'model': 'qwen2.5:1.5b',
```

or:

```python
'model': 'qwen2.5:3b',
```

### AI refusal or weak output

Use the largest model your laptop can run reliably and keep prompts focused on inventory analysis of static text data. On low-resource laptops, stable smaller models are better than a larger model that crashes.

## Disclaimer

GlitchReconAI is for authorized security research, asset inventory, and defensive analysis. Do not use it against systems without permission.
