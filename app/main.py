from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from llm_guard.config import load_settings
from llm_guard.logging_setup import configure_logging, get_logger
from llm_guard.pipeline import SafetyPipeline
from llm_guard.rate_limit import InMemoryRateLimiter
from llm_guard.vector_store import SimpleEncryptedVectorStore


settings = load_settings("/workspace/config/config.yaml")
configure_logging(settings.observability.log_level)
logger = get_logger("app")

app = FastAPI(title=settings.app.name)

pipeline = SafetyPipeline(settings)
rate_limiter = InMemoryRateLimiter(
    qps_per_user=settings.security.resource_exhaustion.qps_per_user,
    qpm_per_user=settings.security.resource_exhaustion.qpm_per_user,
)
vector_store = SimpleEncryptedVectorStore(
    encrypt_at_rest=settings.security.vector_embedding.encrypt_at_rest,
    fernet_key_env=settings.security.vector_embedding.fernet_key_env,
)


class GenerateRequest(BaseModel):
    user_id: str
    role: str = "user"
    prompt: str


class IngestRequest(BaseModel):
    user_id: str
    role: str
    doc_id: str
    text: str
    metadata: Optional[Dict[str, Any]] = None


class QueryRequest(BaseModel):
    user_id: str
    role: str
    query: str
    top_k: int = 5


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok"}


@app.post("/generate")
async def generate(req: GenerateRequest, request: Request) -> Dict[str, Any]:
    if not settings.security.resource_exhaustion.enabled or req.user_id in settings.security.resource_exhaustion.priority_users:
        allowed = True
    else:
        user_key = f"{req.user_id}:{request.client.host if request.client else 'unknown'}"
        allowed = rate_limiter.allow(user_key)

    if not allowed:
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    result = await pipeline.generate(user_id=req.user_id, role=req.role, prompt=req.prompt)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/ingest")
async def ingest(req: IngestRequest) -> Dict[str, Any]:
    if req.role != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    if not settings.security.vector_embedding.enabled:
        raise HTTPException(status_code=400, detail="vector store disabled")
    vector_store.upsert(doc_id=req.doc_id, text=req.text, metadata=req.metadata or {})
    return {"status": "ok", "doc_id": req.doc_id}


@app.post("/query")
async def query(req: QueryRequest) -> Dict[str, Any]:
    if not settings.security.vector_embedding.enabled:
        raise HTTPException(status_code=400, detail="vector store disabled")
    results = vector_store.query(text=req.query, min_similarity=settings.security.vector_embedding.min_similarity, top_k=req.top_k)
    return {"results": [{"doc_id": d, "score": s, "metadata": m} for d, s, m in results]}