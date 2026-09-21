"""Finding model — a confirmed or draft vulnerability."""

from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scope_id: int = Field(foreign_key="scopesession.id", index=True)
    title: str
    vuln_class: str = Field(default="")      # XSS, IDOR, SQLi, SSRF, etc.
    endpoint: str = Field(default="")
    parameter: str = Field(default="")
    http_method: str = Field(default="GET")
    severity: str = Field(default="Medium")  # Critical/High/Medium/Low/Info
    cvss_score: float = Field(default=0.0)
    cvss_vector: str = Field(default="")
    bounty_low: int = Field(default=0)
    bounty_high: int = Field(default=0)
    status: str = Field(default="draft")     # draft/submitted/triaged/resolved/paid
    duplicate_risk: str = Field(default="low")  # low/medium/high
    # Report content
    steps_to_reproduce: str = Field(default="")
    evidence: str = Field(default="")        # Raw HTTP req/res
    impact: str = Field(default="")
    remediation: str = Field(default="")
    notes: str = Field(default="")
    # Analysis chat context
    analysis_summary: str = Field(default="")
    # Dates
    submitted_at: Optional[datetime] = Field(default=None)
    resolved_at: Optional[datetime] = Field(default=None)
    bounty_paid: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class FindingCreate(SQLModel):
    scope_id: int
    title: str
    vuln_class: str = ""
    endpoint: str = ""
    parameter: str = ""
    http_method: str = "GET"
    severity: str = "Medium"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    bounty_low: int = 0
    bounty_high: int = 0
    steps_to_reproduce: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    notes: str = ""
    analysis_summary: str = ""


class FindingUpdate(SQLModel):
    title: Optional[str] = None
    vuln_class: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    http_method: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    bounty_low: Optional[int] = None
    bounty_high: Optional[int] = None
    status: Optional[str] = None
    duplicate_risk: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    evidence: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    notes: Optional[str] = None
    analysis_summary: Optional[str] = None
    submitted_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    bounty_paid: Optional[int] = None


class FindingRead(SQLModel):
    id: int
    scope_id: int
    title: str
    vuln_class: str
    endpoint: str
    parameter: str
    http_method: str
    severity: str
    cvss_score: float
    cvss_vector: str
    bounty_low: int
    bounty_high: int
    status: str
    duplicate_risk: str
    steps_to_reproduce: str
    evidence: str
    impact: str
    remediation: str
    notes: str
    analysis_summary: str
    submitted_at: Optional[datetime]
    resolved_at: Optional[datetime]
    bounty_paid: int
    created_at: datetime
    updated_at: datetime
