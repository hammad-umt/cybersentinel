"""
Lightweight retrieval layer for the Security Copilot.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.models import FirewallAlert, PacketEvent, ResponseAction


@dataclass
class RetrievedChunk:
    text: str
    source: str


class CopilotRetriever:
    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id
        self._vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
        self._matrix = None
        self._chunks: list[RetrievedChunk] = []

    async def build_index(self) -> None:
        chunks: list[RetrievedChunk] = []
        packets = (await self.db.execute(
            select(PacketEvent)
            .where(PacketEvent.user_id == self.user_id)
            .order_by(PacketEvent.timestamp.desc())
            .limit(100)
        )).scalars().all()
        alerts = (await self.db.execute(
            select(FirewallAlert)
            .where(FirewallAlert.user_id == self.user_id)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(100)
        )).scalars().all()
        actions = (await self.db.execute(
            select(ResponseAction)
            .where(ResponseAction.user_id == self.user_id)
            .order_by(ResponseAction.timestamp.desc())
            .limit(50)
        )).scalars().all()

        for event in packets:
            chunks.append(
                RetrievedChunk(
                    source="packet_event",
                    text=(
                        f"Packet event {event.id}: src={event.src_ip} prediction={event.prediction} "
                        f"score={event.threat_score_contribution} at {event.timestamp}"
                    ),
                )
            )
        for alert in alerts:
            chunks.append(
                RetrievedChunk(
                    source="firewall_alert",
                    text=(
                        f"Firewall alert {alert.id}: src={alert.src_ip} severity={alert.severity} "
                        f"score={alert.threat_score} at {alert.timestamp}"
                    ),
                )
            )
        for action in actions:
            chunks.append(
                RetrievedChunk(
                    source="response_action",
                    text=(
                        f"Response action {action.id}: target={action.target_ip} action={action.action} "
                        f"status={action.status} at {action.timestamp}"
                    ),
                )
            )

        self._chunks = chunks
        if not chunks:
            self._matrix = None
            return
        texts = [chunk.text for chunk in chunks]
        self._matrix = self._vectorizer.fit_transform(texts)

    async def retrieve(self, question: str, top_k: int = 5) -> list[RetrievedChunk]:
        if self._matrix is None:
            await self.build_index()
        if not self._chunks or self._matrix is None:
            return []
        query = self._vectorizer.transform([question])
        scores = linear_kernel(query, self._matrix).flatten()
        ranked = sorted(range(len(scores)), key=lambda idx: scores[idx], reverse=True)[:top_k]
        return [self._chunks[idx] for idx in ranked if scores[idx] > 0]


async def _is_external_copilot_url(url: str) -> bool:
    return "/api/copilot/ask" in url or url.rstrip("/").endswith("/ask")


async def _call_external_copilot(question: str, context: str) -> str:
    payload = {
        "question": question,
        "platform_context": {"retrieved_context": context},
    }
    headers = {
        "Authorization": f"Bearer {settings.COPILOT_LLM_API_KEY}"
    } if settings.COPILOT_LLM_API_KEY else {}
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(settings.COPILOT_LLM_BASE_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and "plain_english_summary" in data:
            return data["plain_english_summary"]
        if isinstance(data, dict) and "answer" in data:
            return data["answer"]
        raise ValueError("Unsupported external chatbot response format")


async def _call_openai_style_chatbot(question: str, context: str) -> str:
    payload = {
        "model": settings.COPILOT_LLM_MODEL or "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": "Answer using only the supplied CyberSentinel telemetry context.",
            },
            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
        ],
    }
    headers = {"Authorization": f"Bearer {settings.COPILOT_LLM_API_KEY}"} if settings.COPILOT_LLM_API_KEY else {}
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(settings.COPILOT_LLM_BASE_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]


async def maybe_llm_answer(question: str, chunks: list[RetrievedChunk]) -> str | None:
    if not settings.COPILOT_LLM_BASE_URL:
        return None

    context = "\n".join(f"- {chunk.text}" for chunk in chunks) or "No retrieved context."
    if _is_external_copilot_url(settings.COPILOT_LLM_BASE_URL):
        return await _call_external_copilot(question, context)

    return await _call_openai_style_chatbot(question, context)
