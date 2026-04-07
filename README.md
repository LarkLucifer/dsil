# 🔬 DSIL: Deep Security Intelligence Layer

> **Defensive Security Intelligence Layer (DSIL)** is a professional-grade, async-first bug bounty and automated vulnerability scanning framework. Built for high-performance recon and intelligent vulnerability discovery.

---

## ✨ Key Features

- 🏎️ **Async Ecosystem**: Fully asynchronous pipeline using `aiohttp` and `asyncio` for maximum performance.
- 🤖 **AI-Native Implementation**: Intelligent URL scoring, false-positive assessment, and remediation planning using OpenAI/OpenRouter hooks.
- 🛡️ **Tiered Scanning Strategy**:
    - **Tier 0**: Security Headers & Surface mapping.
    - **Tier 1**: Context-aware XSS & Blind SSRF via OOB.
    - **Tier 2**: Prototype Pollution Reflection.
    - **Tier 5**: JS Secret & Sensitive Logic Analysis (SAST).
- 🤫 **WAF Evasion**: Dynamic header rotation and "Circuit Breaker" global cooldown for stealth.
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

### 2. Configuration

DSIL uses environment variables for sensitive configuration. Copy the example template to get started:

```bash
cp .env.example .env
```

Edit the `.env` file with your credentials:
- `OPENAI_API_KEY`: Required for AI-powered scanning.
- `INTERACTSH_TOKEN`: Optional for private OOB sessions.

---

## 🛠️ Usage

DSIL follows a structured 6-stage pipeline: **Discovery** → **Dedup** → **SAST** → **Tiers** → **Verify** → **OOB** → **Report**.

### Basic Proof-of-Concept
```bash
dsil --target https://example.com poc
```

### Deep Scanning (The Bug Bounty Workflow)
```bash
dsil --target https://example.com scan --verbose --enable-ai
```

### Static Analysis Only
```bash
dsil --target https://example.com sast
```

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
