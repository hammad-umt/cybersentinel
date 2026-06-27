"""
Data-grounded Security Copilot service.

This is a retrieval layer over CyberSentinel's own telemetry. It can later be
connected to an LLM, but the current answer is deterministic and traceable to
packet events, firewall alerts, response actions, and threat scoring output.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import FirewallAlert, PacketEvent, ResponseAction
from schemas.copilot import CopilotAnswerResponse, CopilotQuestionRequest
from core.severity import CRITICAL, HIGH, MEDIUM, translate_firewall_severity
from services.copilot_rag import CopilotRetriever, maybe_llm_answer
from services.threat_scoring_service import ThreatScoringService


class CopilotService:
    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id

    async def answer(self, request: CopilotQuestionRequest) -> CopilotAnswerResponse:
        retriever = CopilotRetriever(self.db, self.user_id)
        chunks = await retriever.retrieve(request.question)
        llm_answer = await maybe_llm_answer(request.question, chunks)
        if llm_answer:
            return CopilotAnswerResponse(
                answer=llm_answer,
                confidence="rag-llm-summary",
                recommended_actions=[
                    "Review cited telemetry in the dashboard and alert history.",
                ],
                evidence={"retrieved_chunks": [chunk.text for chunk in chunks]},
            )

        ip = request.ip or _extract_ip(request.question)
        if ip:
            return await self._answer_for_ip(request.question, ip)
        return await self._answer_global(request.question)

    async def _answer_for_ip(self, question: str, ip: str) -> CopilotAnswerResponse:
        packets = (await self.db.execute(
            select(PacketEvent)
            .where(PacketEvent.user_id == self.user_id, PacketEvent.src_ip == ip)
            .order_by(PacketEvent.timestamp.desc())
            .limit(10)
        )).scalars().all()
        alerts = (await self.db.execute(
            select(FirewallAlert)
            .where(FirewallAlert.user_id == self.user_id, FirewallAlert.src_ip == ip)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(10)
        )).scalars().all()
        actions = (await self.db.execute(
            select(ResponseAction)
            .where(ResponseAction.user_id == self.user_id, ResponseAction.target_ip == ip)
            .order_by(ResponseAction.timestamp.desc())
            .limit(5)
        )).scalars().all()

        score = await ThreatScoringService(self.db, self.user_id).score(
            ip, {"source": "copilot", "question": question}
        )
        latest_alert = alerts[0] if alerts else None

        if latest_alert:
            answer = (
                f"{ip} currently scores {score.final_score}/100 ({score.severity}). "
                f"The latest firewall alert is {translate_firewall_severity(latest_alert.severity)} with score "
                f"{latest_alert.threat_score:.1f}, and {len(alerts)} recent alert(s) "
                f"were found for this IP."
            )
        else:
            answer = (
                f"{ip} currently scores {score.final_score}/100 ({score.severity}). "
                f"No stored firewall alerts were found, and {len(packets)} packet event(s) "
                f"are available for review."
            )

        recommendations = _recommend(score.severity, bool(actions))
        return CopilotAnswerResponse(
            answer=answer,
            recommended_actions=recommendations,
            evidence={
                "ip": ip,
                "unified_score": score.model_dump(),
                "packet_event_count": len(packets),
                "firewall_alert_count": len(alerts),
                "response_action_count": len(actions),
                "recent_alert_ids": [alert.id for alert in alerts],
                "recent_action_ids": [action.id for action in actions],
            },
        )

    async def _answer_global(self, question: str) -> CopilotAnswerResponse:
        alerts = (await self.db.execute(
            select(FirewallAlert)
            .where(FirewallAlert.user_id == self.user_id)
            .order_by(FirewallAlert.threat_score.desc(), FirewallAlert.timestamp.desc())
            .limit(5)
        )).scalars().all()
        packets = (await self.db.execute(
            select(PacketEvent)
            .where(PacketEvent.user_id == self.user_id)
            .order_by(PacketEvent.timestamp.desc())
            .limit(5)
        )).scalars().all()

        if alerts:
            top = alerts[0]
            answer = (
                f"The highest current stored threat is {top.src_ip} with firewall score "
                f"{top.threat_score:.1f} ({translate_firewall_severity(top.severity)}). I found {len(alerts)} high-priority "
                f"alert candidate(s) and {len(packets)} recent packet event(s) for context."
            )
        else:
            answer = (
                "No stored firewall alerts are available yet. Recent packet telemetry is "
                f"available for {len(packets)} event(s), so start with live capture or upload "
                "a firewall log to generate richer investigation context."
            )

        return CopilotAnswerResponse(
            answer=answer,
            recommended_actions=[
                "Review /api/v1/dashboard/summary for SOC-level counts.",
                "Upload or monitor firewall logs if alert context is empty.",
            ],
            evidence={
                "question": question,
                "top_alert_ids": [alert.id for alert in alerts],
                "recent_packet_event_ids": [event.id for event in packets],
            },
        )


def _extract_ip(text: str) -> str | None:
    import re

    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return match.group(0) if match else None


def _recommend(severity: str, has_actions: bool) -> list[str]:
    if severity == CRITICAL:
        actions = ["Block the IP or add it to the watchlist from the Threat Response Center."]
    elif severity in {HIGH, MEDIUM, CRITICAL}:
        actions = ["Investigate firewall evidence and enrich the IP reputation before blocking."]
    else:
        actions = ["Continue monitoring and compare with future packet/firewall activity."]
    if has_actions:
        actions.append("Review existing response audit entries before taking another action.")
    return actions
