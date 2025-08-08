# LLM Security Guard (OWASP LLM Top 10)

A configurable FastAPI service that wraps LLM generation with automated detection and response aligned to OWASP LLM Top 10 focus areas:
- LLM01 Prompt Injection
- LLM02 Sensitive Information Disclosure
- LLM07 System Prompt Disclosure
- LLM05 Improper Output Handling
- LLM08 Vector & Embedding Weaknesses (basic protections)
- LLM09 Inaccurate or Misleading Information (basic checks)
- LLM10 Resource Exhaustion

## Quickstart

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Configure settings in `config/config.yaml` (model provider, rules, thresholds).

3. Run the API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

4. Try the generate endpoint:

```bash
curl -X POST http://localhost:8000/generate \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"demo","role":"user","prompt":"Explain rate limiting"}'
```

## Configuration

All knobs live in `config/config.yaml`. Model usage is optional; by default a DummyModelProvider is used so the service can run without API keys. To use a real model, set `model.provider` and corresponding API keys in env or config.

## Endpoints
- POST `/generate`: Safe guarded text generation pipeline
- POST `/ingest`: Ingest text into protected vector store (basic demo)
- POST `/query`: Query the vector store with similarity threshold
- GET `/health`: Health check

## Notes
- This reference implements baseline, extensible guards. For production, integrate your SIEM, real fact-check sources, proper embeddings/vector DB, and persistent stores.
- All detectors are configurable. See `llm_guard/config.py` for env overrides.
