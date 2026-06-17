"""
Pydantic schemas for the Threat Response Center.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


ResponseActionType = Literal[
    "block_ip",
    "unblock_ip",
    "remove_firewall_rule",
    "whitelist",
    "watchlist",
]


class ResponseActionRequest(BaseModel):
    target_ip: str = Field(description="IP address to act on")
    action: ResponseActionType
    reason: Optional[str] = None
    requested_by: Optional[str] = None
    execute: bool = Field(
        default=False,
        description="When false, records a dry-run audit action without changing firewall state.",
    )


class ResponseActionOut(BaseModel):
    id: str
    timestamp: str
    target_ip: str
    action: str
    status: str
    requested_by: Optional[str] = None
    reason: Optional[str] = None
    command_preview: Optional[str] = None
    result_message: Optional[str] = None
    executed: bool

    model_config = {"from_attributes": True}


class ResponseActionResponse(BaseModel):
    success: bool = True
    action: ResponseActionOut


class ResponseActionsResponse(BaseModel):
    success: bool = True
    total: int
    page: int
    page_size: int
    actions: List[ResponseActionOut]
