# RAG + LLM Security Gateway Integration

This example demonstrates how an enterprise RAG application integrates with the **LLM Security Gateway** as an external HTTP microservice.

## Architecture

```
User Query
    │
    ▼
[RAG Application]
    │
    ├── 1. POST /v1/check/input ──► [LLM Security Gateway]
    │                                ├── PII Scrubbing
    │                                ├── Prompt Injection Detection
    │                                └── Policy Enforcement
    │
    │   ◄── Decision: ALLOW / BLOCK / REDACT ──┘
    │
    ├── (If ALLOW / REDACT sanitized text):
    │   ├── 2. Vector DB Hybrid Search (Qdrant + BM25)
    │   ├── 3. LLM Generation (Groq / OpenAI)
    │   │
    │   └── 4. POST /v1/check/output ──► [LLM Security Gateway]
    │                                     ├── PII Leakage Detection
    │                                     ├── Factual Grounding Guard
    │                                     └── Toxicity Validation
    │
    │   ◄── Verified / Sanitized Response ────┘
    ▼
Safe Response to User
```

## Running the Demo

1. Start the LLM Security Gateway:
   ```bash
   uvicorn app.main:app --port 8000
   ```

2. Run the integration demo script:
   ```bash
   python examples/rag_integration/rag_gateway_demo.py
   ```
