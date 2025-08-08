from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.fernet import Fernet


@dataclass
class VectorRecord:
    doc_id: str
    tokens_set: set[str]
    metadata: dict


class SimpleEncryptedVectorStore:
    def __init__(self, encrypt_at_rest: bool, fernet_key_env: str) -> None:
        self.encrypt_at_rest = encrypt_at_rest
        self.fernet: Optional[Fernet] = None
        if encrypt_at_rest:
            key = os.getenv(fernet_key_env)
            if not key:
                key = base64.urlsafe_b64encode(os.urandom(32)).decode()
                os.environ[fernet_key_env] = key
            self.fernet = Fernet(key)
        self._store: Dict[str, bytes | str] = {}
        self._index: Dict[str, VectorRecord] = {}

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        return set([t for t in text.lower().split() if t.strip()])

    def _encrypt(self, text: str) -> bytes | str:
        if self.fernet:
            return self.fernet.encrypt(text.encode("utf-8"))
        return text

    def _decrypt(self, blob: bytes | str) -> str:
        if self.fernet and isinstance(blob, (bytes, bytearray)):
            return self.fernet.decrypt(blob).decode("utf-8")
        if isinstance(blob, (bytes, bytearray)):
            return blob.decode("utf-8")
        return blob

    def upsert(self, doc_id: str, text: str, metadata: Optional[dict] = None) -> None:
        metadata = metadata or {}
        tokens_set = self._tokenize(text)
        payload = json.dumps({"text": text, "metadata": metadata})
        stored = self._encrypt(payload)
        self._store[doc_id] = stored
        self._index[doc_id] = VectorRecord(doc_id=doc_id, tokens_set=tokens_set, metadata=metadata)

    def similarity(self, a_tokens: set[str], b_tokens: set[str]) -> float:
        if not a_tokens or not b_tokens:
            return 0.0
        inter = len(a_tokens & b_tokens)
        union = len(a_tokens | b_tokens)
        return inter / union if union else 0.0

    def query(self, text: str, min_similarity: float, top_k: int = 5) -> List[Tuple[str, float, dict]]:
        query_tokens = self._tokenize(text)
        scored: List[Tuple[str, float, dict]] = []
        for doc_id, record in self._index.items():
            score = self.similarity(query_tokens, record.tokens_set)
            if score >= min_similarity:
                scored.append((doc_id, score, record.metadata))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def get(self, doc_id: str) -> Tuple[str, dict] | None:
        blob = self._store.get(doc_id)
        if blob is None:
            return None
        payload = self._decrypt(blob)
        data = json.loads(payload)
        return data["text"], data.get("metadata", {})