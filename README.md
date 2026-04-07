# 🔬 DSIL: Deep Security Intelligence Layer

> **Defensive Security Intelligence Layer (DSIL)** is a professional-grade, async-first bug bounty and automated vulnerability scanning framework. Built for high-performance recon and intelligent vulnerability discovery.

---

## ✨ Key Features

- 🏎️ **Async Ecosystem**: Fully asynchronous pipeline using `aiohttp` and `asyncio` for maximum performance.
- 🚀 **Memory Optimized (v2.0)**: Uses a worker-pool pattern to handle millions of discovered URLs without OOM (Out-of-Memory) crashes on standard VPS hardware.
- 🤖 **AI-Native Implementation**: Intelligent URL scoring, false-positive assessment, and remediation planning using OpenAI/OpenRouter hooks.
- 🛡️ **Tiered Scanning Strategy**:
    - **Tier 0**: Security Headers & Surface mapping.
    - **Tier 1**: Context-aware XSS & Blind SSRF via OOB.
    - **Tier 2**: Prototype Pollution Reflection.
    - **Tier 5**: JS Secret & Sensitive Logic Analysis (SAST) + **Nuclei Integration**.
- 🤫 **WAF Evasion**: Dynamic header rotation and "Circuit Breaker" global cooldown for stealth.
- 🗡️ **Robust Discovery**: Enhanced **Katana** integration with automatic fallback for headless-related errors.
- 📡 **OOB Integration**: Native support for **Interactsh** to detect blind vulnerabilities.
- 📝 **Bug Bounty Ready Reports**: Generates professional markdown reports formatted for **HackerOne** and **Intigriti** platforms.

---

## 🚀 Getting Started

### 1. Installation

DSIL supports Python 3.10+. We recommend using a virtual environment.

```bash
# Clone and enter directory
cd dsil

# Set up environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode
pip install -e .
```

### 2. Prerequisite Tools (Linux)
For full discovery functionality, ensure the following are in your `$PATH`:
- [Katana](https://github.com/projectdiscovery/katana)
- [Nuclei](https://github.com/projectdiscovery/nuclei)

---

## 🛠️ Usage

### Basic Proof-of-Concept
```bash
dsil --target https://example.com poc
```

### Deep Scanning (The Bug Bounty Workflow)
```bash
dsil --target https://example.com scan --verbose --enable-ai
```

### 🚅 Optimized for VPS/Low-RAM Machines
If you encouter memory pressure or want to scan massive targets:
```bash
# Limit crawl depth and parallel tasks
dsil --target https://massive-site.com scan --max-pages 500 --concurrency 10
```

| Flag | Default | Description |
|------|---------|-------------|
| `--max-pages` | 200 | Maximum unique pages to crawl during discovery. |
| `--concurrency` | 20 | Number of parallel scanner workers. Reduce for low-RAM systems. |

---

## 📄 Reporting

All reports are saved in the `reports/` directory with a timestamped stem.
- **JSON**: Raw machine-readable data.
- **HTML**: Visual interactive report.
- **Markdown**: Standard documentation.
- **H1_Report**: Submission-ready report for HackerOne/Intigriti.

---

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always obtain permission before scanning a target.

