"""Recon result and timeline entry models."""

from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field


class ReconResult(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scope_id: int = Field(foreign_key="scopesession.id", index=True)
    result_type: str = Field(index=True)   # subdomain/tech/js_endpoint/js_secret/header_issue/cve/robots
    target: str                             # The URL or domain this result is for
    title: str = Field(default="")
    data: str = Field(default="{}")        # JSON blob of raw data
    score: int = Field(default=0)          # 0-10 priority score
    score_reason: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ReconResultRead(SQLModel):
    id: int
    scope_id: int
    result_type: str
    target: str
    title: str
    data: dict
    score: int
    score_reason: str
    created_at: datetime


class TimelineEntry(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    event_type: str  # submitted/triaged/bounty_offered/resolved/paid/escalated/custom
    event_date: datetime
    notes: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TimelineEntryCreate(SQLModel):
    finding_id: int
    event_type: str
    event_date: datetime
    notes: str = ""


class TimelineEntryRead(SQLModel):
    id: int
    finding_id: int
    event_type: str
    event_date: datetime
    notes: str
    created_at: datetime
