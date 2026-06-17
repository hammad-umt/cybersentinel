"""
Pydantic schemas for CyberSentinel's data-grounded Security Copilot.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CopilotQuestionRequest(BaseModel):
    question: str = Field(min_length=3, max_length=1000)
    ip: Optional[str] = Field(default=None, description="Optional IP address to focus the answer")


class CopilotAnswerResponse(BaseModel):
    success: bool = True
    answer: str
    confidence: str = "data-grounded-summary"
    recommended_actions: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
