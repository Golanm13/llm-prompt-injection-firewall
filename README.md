# LLM-Firewall

## Overview

LLM-Firewall is a prompt security guardrail engine designed to protect large language model workflows from prompt injection, data exfiltration attempts, and roleplay-based jailbreaks. The project uses a two-stage architecture: a fast Regex-based firewall for initial detection, followed by a Gemini Judge model for context-aware validation of high-risk prompts.

This design balances defensive speed with semantic accuracy. The first layer rejects clearly malicious prompts quickly, while the second layer helps reduce false positives in legitimate academic, testing, or security-research scenarios.

## Key Features

- Dual-layer defense with Regex rule matching and LLM-as-a-Judge validation.
- Semantic verification using the Google Gemini API for high-risk prompts.
- Structured audit logging for every prompt decision.
- Real-time observability dashboard built with Streamlit.
- Rate limiting and API hardening for the FastAPI proxy endpoint.

## Tech Stack

- FastAPI for the backend API and proxy service.
- Streamlit for the observability dashboard.
- Google GenAI SDK for Gemini model access.
- SlowAPI for rate limiting.
- Python standard library utilities for logging and file handling.

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment variables

Create a `.env` file in the project root and set your Gemini API key:

```env
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

### 3. Start the FastAPI proxy app

Open the first terminal window and run:

```bash
uvicorn src.main:app --reload --port 8000
```

The proxy endpoint is available at:

```text
http://localhost:8000/api/v1/proxy
```

### 4. Start the Streamlit dashboard

Open a second terminal window and run:

```bash
streamlit run dashboard.py
```

The dashboard reads from `firewall_audit.jsonl` in the project root and shows:

- Total requests vs. blocked requests.
- Distribution of blocked categories.
- The 20 most recent firewall events.

## Security Logic

The firewall uses a performance-first pipeline with a semantic fallback.

### Why Regex First

Regex rules are extremely fast, deterministic, and cheap to evaluate. They are ideal for catching obvious injection patterns such as system prompt overrides, exfiltration commands, and roleplay-based attacks. This makes the first layer suitable for blocking the majority of malicious traffic with minimal latency.

### Why Gemini Second

Regex alone can be overly rigid and may flag harmless prompts that contain suspicious-looking language in an academic, debugging, or security-testing context. The Gemini Judge model acts as a semantic verifier for high-risk prompts, helping distinguish genuine threats from false positives.

### Trade-off: Performance vs. Accuracy

- Regex provides high throughput and predictable behavior.
- Gemini adds contextual accuracy, but with additional latency and API dependency.

The combined design is intentionally layered: fast pattern matching first, then deeper semantic judgment only when needed.

## Future Improvements

- Add more fine-grained Regex rules for specialized prompt injection variants.
- Support local LLM judges to improve privacy and reduce external API dependence.
- Add authentication and role-based access control to the dashboard.
- Extend observability with filtering, search, and export tools for audit events.
- Add structured alerts for repeated blocked requests or rate-limit violations.

## Project Structure

```text
README.md
dashboard.py
firewall_audit.jsonl
requirements.txt
src/
  api/
  schemas/
  services/
  main.py
tests/
```

## Notes

- The dashboard handles a missing or partially written audit log gracefully.
- The backend writes audit events in JSONL format for simple ingestion and analysis.
- If you change the Gemini model name, update `GEMINI_MODEL` in `.env`.
