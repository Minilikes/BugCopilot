"""Scope session model — the authorization gate for all recon actions."""

from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field


class ScopeSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    program_name: str = Field(index=True)
    platform: str = Field(default="")        # HackerOne / Bugcrowd / Intigriti / Other
    scope_url: str = Field(default="")       # Link to program's scope page
    authorized: bool = Field(default=False)  # User confirmed authorization
    auth_note: str = Field(default="")       # Written permission or program link
    in_scope_patterns: str = Field(default="[]")   # JSON list of patterns/wildcards
    out_scope_patterns: str = Field(default="[]")  # JSON list of patterns/wildcards
    target_domain: str = Field(default="")   # Primary domain being tested
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ── Pydantic schemas (for API request/response) ───────────────────────────────

class ScopeSessionCreate(SQLModel):
    program_name: str
    platform: str = ""
    scope_url: str = ""
    authorized: bool
    auth_note: str = ""
    in_scope_patterns: list[str] = []
    out_scope_patterns: list[str] = []
    target_domain: str = ""


class ScopeSessionRead(SQLModel):
    id: int
    program_name: str
    platform: str
    scope_url: str
    authorized: bool
    auth_note: str
    in_scope_patterns: list[str]
    out_scope_patterns: list[str]
    target_domain: str
    is_active: bool
    created_at: datetime
