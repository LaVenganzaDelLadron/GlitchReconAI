# GlitchReconAI

GlitchReconAI is a CLI reconnaissance automation tool for authorized security research workflows. It runs passive recon tools, parses their output, and sends collected results to a local Ollama model for structured analysis and safe review suggestions.

This project is intended for analyzing collected reconnaissance output. It does not perform exploitation.

## Features

- Interactive command-line menu.
- Subfinder support for:
  - single target domains
  - target list files
  - all-sources mode
- Katana passive web crawling with:
  - URL discovery
  - JavaScript crawling
  - technology detection
  - known-file discovery
- Passive URL and asset collection through:
  - waybackurls
  - assetfinder
  - gau
  - httpx
- Structured parsing for:
  - URLs
  - JavaScript files
  - API-like paths
  - interesting paths such as login, admin, upload, graphql, config, backup, and auth paths
- Local AI analysis through Ollama.
- Modular project layout for future recon, intelligence, scanning, web, reporting, and ML features.

## Requirements

The recon tools are lightweight. The heavy part is local AI analysis through Ollama, especially on laptops with limited RAM or unsupported AMD Radeon GPU acceleration.

### Minimum: CLI recon only

- Debian, Kali, Ubuntu, or another Linux system with equivalent packages
- Python 3
- Python packages from `requirements.txt`
- Go, used to install the external recon binaries
- `figlet` and `lolcat` for banner output
- Internet access for passive recon tool queries
- External recon tools installed as needed and available in your `PATH`:
  - `subfinder`
  - `katana`
  - `waybackurls`
  - `assetfinder`
  - `gau`
  - `httpx`

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

These commands target Debian, Kali, and Ubuntu.

### 1. Install system packages

```bash
sudo apt update
sudo apt install python3 python3-pip golang figlet lolcat
```

### 2. Install Python packages

Run this from the project root:

```bash
python3 -m pip install -r requirements.txt
```

`requirements.txt` installs Python packages only. External recon tools such as `subfinder`, `katana`, and `gau` are command-line binaries and are installed separately below.

### 3. Add Go binaries to PATH

Go installs tools into `~/go/bin` by default. Add it to your current shell:

```bash
export PATH=$PATH:~/go/bin
```

To make it permanent for Bash:

```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

For Zsh:

```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.zshrc
source ~/.zshrc
```

### 4. Install recon tools

Install Subfinder:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Install Katana:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Install waybackurls:

```bash
go install github.com/tomnomnom/waybackurls@latest
```

Install assetfinder:

```bash
go install github.com/tomnomnom/assetfinder@latest
```

Install gau:

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

Install httpx:

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Confirm the tools are available:

```bash
subfinder -version
katana -version
waybackurls -h
assetfinder -h
gau --version
httpx -version
```

### 5. Install Ollama for AI analysis

Ollama is optional for collecting recon data, but the current agents send collected output to Ollama for AI analysis. Install and start Ollama, then pull a model.

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
    [3] Waybackurls
    [4] Assetfinder
    [5] GAU
    [6] httpx
```

Input examples:

- Subfinder single-target or all-sources mode: `example.com`
- Subfinder list mode: path to a file containing target domains
- Katana mode: `https://example.com`
- Waybackurls mode: `example.com` or an authorized target domain
- Assetfinder mode: `example.com`
- GAU mode: `example.com`
- httpx mode: path to a file containing targets


### AI request

The AI client sends an HTTP POST request to local Ollama:

```text
POST http://localhost:11434/api/generate
model: qwen2.5:7b
stream: false or true
```

## Current Project Flow

- `glitch.py` starts the app.
- `view/start.py` handles the main menu and module selection.
- `view/recon.py` lets the user choose Subfinder, Katana, waybackurls, assetfinder, GAU, or httpx and collects target input.
- `core/agent.py` runs the selected recon tool and sends results for AI analysis.
- `tools/recon/subfinder.py` wraps the Subfinder command.
- `tools/recon/katana.py` wraps Katana and parses URLs, JavaScript files, API-like paths, and interesting paths.
- `tools/recon/waybackurls.py` wraps waybackurls and classifies archived URLs.
- `tools/recon/assetfinder.py` wraps assetfinder subdomain discovery.
- `tools/recon/gau.py` wraps gau and classifies passive URL output.
- `tools/recon/httpx.py` wraps httpx target probing.
- `ai/prompt_engine.py` builds recon analysis prompts.
- `ai/ollama_client.py` sends prompts to local Ollama.
- `ai/analyzer.py` connects the prompt builder and Ollama client.

## AI Analysis

GlitchReconAI sends collected recon output to a local Ollama model and asks for structured inventory-style analysis. The current recommended model is:

```text
qwen2.5:7b
```

AI suggestions are intended as leads for manual review only. They should not be treated as proof of vulnerabilities.

## Low-resource laptop setup

If your laptop has only 8GB RAM or an AMD Radeon GPU that Ollama does not accelerate correctly:

- Start with `qwen2.5:1.5b`.
- Try `qwen2.5:3b` if the smaller model is stable.
- Avoid `qwen2.5:7b` until you confirm your system has enough free RAM or working GPU acceleration.
- Close browsers, IDEs, virtual machines, and other heavy apps before AI analysis.
- Run recon collection first, then run AI analysis after you have the output.
- If Ollama falls back to CPU, expect slower responses and higher system memory pressure.

## Notes

- Only use this tool against domains you own or are authorized to assess.
- The AI output is based on text patterns only and should not be treated as proof of vulnerabilities.
- Katana support is limited to passive crawling and output parsing.
- GlitchReconAI does not include exploitation logic, vulnerability confirmation, payload generation, or active attack behavior.
- Some folders and modules are placeholders for future expansion.
- Current implemented recon flow includes Subfinder, Katana, waybackurls, assetfinder, GAU, and httpx.

## Troubleshooting

### `ModuleNotFoundError`

Install Python dependencies and run the app from the project root:

```bash
python3 -m pip install -r requirements.txt
python3 glitch.py
```

### Banner commands fail

Install `figlet` and `lolcat`:

```bash
sudo apt install figlet lolcat
```

### Recon tool is not installed or not in PATH

Make sure `~/go/bin` is in your `PATH`:

```bash
export PATH=$PATH:~/go/bin
```

Then install the missing tool from the installation section.

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
