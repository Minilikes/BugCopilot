"""Target model for the Target Picker (Module 6)."""

from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    platform: str = Field(default="")         # HackerOne / Bugcrowd / Intigriti / Other
    program_url: str = Field(default="")
    scope_count: int = Field(default=0)        # Number of in-scope assets
    avg_payout: int = Field(default=0)         # USD
    max_payout: int = Field(default=0)         # USD
    program_age_days: int = Field(default=0)   # Days since program launched
    response_rating: float = Field(default=0.0)  # 0-5 reputation score
    asset_types: str = Field(default="[]")     # JSON: ["web","api","mobile"]
    tech_tags: str = Field(default="[]")       # JSON: ["react","nodejs","aws"]
    notes: str = Field(default="")
    priority_score: float = Field(default=0.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TargetCreate(SQLModel):
    name: str
    platform: str = ""
    program_url: str = ""
    scope_count: int = 0
    avg_payout: int = 0
    max_payout: int = 0
    program_age_days: int = 0
    response_rating: float = 0.0
    asset_types: list[str] = []
    tech_tags: list[str] = []
    notes: str = ""


class TargetRead(SQLModel):
    id: int
    name: str
    platform: str
    program_url: str
    scope_count: int
    avg_payout: int
    max_payout: int
    program_age_days: int
    response_rating: float
    asset_types: list[str]
    tech_tags: list[str]
    notes: str
    priority_score: float
    created_at: datetime


class TargetFilter(SQLModel):
    platform: Optional[str] = None
    asset_types: Optional[list[str]] = None
    tech_tags: Optional[list[str]] = None
    min_payout: Optional[int] = None
