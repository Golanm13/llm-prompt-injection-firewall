# LLM-Firewall

## Overview

**LLM-Firewall** is a prompt security guardrail engine designed to protect Large Language Model (LLM) workflows from:

- Prompt injection
- Data exfiltration attempts
- Roleplay-based jailbreak attacks

The project uses a **two-stage architecture**:

1. **Regex-based Firewall** — fast initial detection.
2. **LLM-as-a-Judge Validation Layer** — context-aware validation of high-risk prompts.

This design balances **defensive speed** with **semantic accuracy**.

The first layer rejects clearly malicious prompts quickly, while the second layer reduces false positives in legitimate academic, testing, or security-research scenarios using the **Google Gemini API**, with an automated local fallback to **Ollama** if the upstream API becomes unavailable.

---

## Key Features

- **Dual-Layer Defense**  
  Regex rule matching combined with LLM-as-a-Judge validation.

- **Semantic Verification**  
  Google Gemini API integration for evaluating high-risk and ambiguous prompts.

- **Robust Local Fallback**  
  Automated transition to local Ollama models (e.g., Llama 3) to handle:
  - API timeouts
  - `429 Rate Limits`
  - Connectivity failures  
  *(Fail-Secure architecture)*

- **Synchronous Audit Logging**  
  Inline event logging to guarantee threat intelligence persistence (`JSONL` format), even during execution faults or upstream API crashes.

- **Real-Time Observability**  
  Interactive dashboard built with Streamlit for monitoring:
  - Blocked vs. allowed traffic
  - Risk categories

- **API Hardening**  
  Rate limiting (**SlowAPI**) and strict **Pydantic** payload validation on the FastAPI proxy endpoint.

---

## Tech Stack

| Component | Purpose |
|----------|---------|
| FastAPI | Backend API and proxy service |
| Streamlit | Observability and monitoring dashboard |
| Google GenAI SDK | Cloud-based semantic model access |
| Ollama | Local offline fallback modeling |
| SlowAPI | In-memory rate limiting |
| Pytest | Test suite with `monkeypatch` for mocked judge evaluations |

---

# How to Run
> [!NOTE]
> **Windows Users (PowerShell):** If you encounter an execution policy error when trying to activate the virtual environment, run the following command in your terminal **before** activation:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
> \venv\Scripts\Activate.
> ```
## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 2. Configure Environment Variables

Create a `.env` file in the project root based on `.env.example`.

```env
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-3.1-flash-lite
OLLAMA_HOST=http://localhost:11434
```

---

## 3. Start Local Ollama (Fallback Requirement)

Ensure Ollama is installed and running locally.

Pull/start the target model in a dedicated terminal:

```bash
ollama run llama3
```

---

## 4. Execute the System

### Run all components simultaneously

(FastAPI backend + Streamlit dashboard)

```bash
python run_demo.py
```

### Or run manually in separate terminals

Start the FastAPI proxy server:

```bash
uvicorn src.main:create_app --reload
```

Start the Streamlit dashboard:

```bash
streamlit run dashboard.py
```

---

# Architecture & Security Logic

The firewall uses a **performance-first pipeline with semantic fallback**.

## Why Regex First (Strengths)

Regex rules are:
- Extremely fast
- Deterministic
- Cheap to evaluate (`O(N)` time complexity with RE2-style engines / length constraints)

They are ideal for catching obvious injection patterns such as:
- System prompt overrides
- Exfiltration commands
- Roleplay-based attacks

This makes the first layer suitable for blocking the majority of malicious traffic with **near-zero latency**.

---

## Why LLM-as-a-Judge Second (Mitigating Weaknesses)

Regex alone can be overly rigid and may flag harmless prompts containing suspicious-looking language in:
- Academic contexts
- Debugging scenarios
- Security testing

The LLM Judge acts as a **semantic verifier** for high-risk prompts and helps distinguish genuine threats from false positives.

---

## Trade-offs

### Performance vs. Accuracy

| Regex | LLM |
|-------|-----|
| High throughput | Higher semantic accuracy |
| Deterministic | Context-aware |
| Near-zero latency | Added network latency |
| No API cost | Potential API costs |

---

### Cloud vs. Local

| Gemini | Ollama |
|---------|--------|
| Strong reasoning | Full local execution |
| Faster responses | Zero API cost |
| External dependency | Higher compute requirements |
| Possible rate limits | Slower cold starts |

---

# Future Improvements

- Add fine-grained Regex rules for specialized prompt injection variants (e.g., localized languages).
- Transition to a fully local **Small Language Model (SLM)** judge to improve privacy and eliminate external API dependence.
- Implement authentication (**JWT**) and role-based access control (**RBAC**) for dashboard access.
- Extend observability with:
  - Dynamic filtering
  - Search
  - CSV export
- Add structured alerting mechanisms:
  - Slack webhooks
  - Email notifications
  - Repeated blocked request alerts
  - Rate-limit violation alerts

---

# Project Structure

LLM_Firewall_Project/
├── docs/                             # Project documentation and extended design resources
├── src/                              # Main application source code
│   ├── api/                          # HTTP transport layer and endpoints
│   │   ├── routes/
│   │   │   ├── proxy.py              # Central firewall proxy routing logic
│   │   │   └── __init__.py
│   │   └── __init__.py
│   ├── frontend/                     # User interface layer
│   │   └── app.py                    # Streamlit telemetry and metrics dashboard app
│   ├── schemas/                      # Data validation and API contracts
│   │   ├── proxy.py                  # Pydantic request and response models
│   │   └── __init__.py
│   ├── services/                     # Core business logic and security modules
│   │   ├── audit_logger.py           # Thread-safe local JSON Lines event logging
│   │   ├── decision_logic.py         # Dual-layer guardrails engine (Regex + LLM Judge)
│   │   └── __init__.py
│   ├── main.py                       # Application bootstrap and environment provisioning
│   └── __init__.py
├── tests/                            # Automation and validation test suite
│   ├── test_decision_logic.py        # Isolated unit tests for the guardrail rules
│   └── test_proxy.py                 # Integration tests for HTTP endpoint behavior
├── .env                              # Local runtime environment configurations and secrets
├── .env.example                      # Distribution template for setting environment keys
├── conftest.py                       # Global pytest orchestration settings and fixtures
├── dashboard.py                      # Root execution entrypoint for the Streamlit UI
├── README.md                         # Comprehensive documentation and project manual
├── requirements.txt                  # Fixed list of third-party package dependencies
├── run_demo.bat                      # Windows batch utility for multi-service execution
└── test_gemini.py                    # Diagnostic pipeline verification script for Gemini API
