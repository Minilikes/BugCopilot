"""Target Picker router — ranks bug bounty programs by opportunity score."""

import json
import math
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from backend.db import get_session
from backend.models.target import Target, TargetCreate, TargetRead

router = APIRouter()


def _compute_score(t: Target) -> float:
    """
    Priority score formula:
    - Scope breadth: 30% (more assets = more attack surface)
    - Payout: 30% (higher avg payout = better ROI)
    - Newness: 20% (newer programs = less picked-over)
    - Response rating: 20% (faster triagers = better experience)
    """
    # Scope breadth: normalize 0-100 assets to 0-1 (log scale)
    scope_score = min(math.log1p(t.scope_count) / math.log1p(100), 1.0) if t.scope_count > 0 else 0

    # Payout: normalize 0-10000 to 0-1 (log scale)
    payout_score = min(math.log1p(t.avg_payout) / math.log1p(10000), 1.0) if t.avg_payout > 0 else 0

    # Newness: programs < 180 days old score highest; > 3 years score lowest
    if t.program_age_days <= 0:
        newness_score = 0.5  # unknown age
    elif t.program_age_days < 180:
        newness_score = 1.0
    elif t.program_age_days < 365:
        newness_score = 0.8
    elif t.program_age_days < 730:
        newness_score = 0.6
    elif t.program_age_days < 1095:
        newness_score = 0.4
    else:
        newness_score = 0.2

    # Response rating: 0-5 → 0-1
    response_score = min(t.response_rating / 5.0, 1.0) if t.response_rating > 0 else 0.5

    total = (
        scope_score * 0.30 +
        payout_score * 0.30 +
        newness_score * 0.20 +
        response_score * 0.20
    )
    return round(total * 100, 1)  # scale to 0-100


def _to_read(t: Target) -> TargetRead:
    return TargetRead(
        id=t.id,
        name=t.name,
        platform=t.platform,
        program_url=t.program_url,
        scope_count=t.scope_count,
        avg_payout=t.avg_payout,
        max_payout=t.max_payout,
        program_age_days=t.program_age_days,
        response_rating=t.response_rating,
        asset_types=json.loads(t.asset_types or "[]"),
        tech_tags=json.loads(t.tech_tags or "[]"),
        notes=t.notes,
        priority_score=t.priority_score,
        created_at=t.created_at,
    )


@router.get("/", response_model=list[TargetRead])
def list_targets(
    platform: str | None = None,
    asset_type: str | None = None,
    tech_tag: str | None = None,
    db: Session = Depends(get_session),
):
    targets = db.exec(select(Target).order_by(Target.priority_score.desc())).all()

    # Filter
    if platform:
        targets = [t for t in targets if t.platform.lower() == platform.lower()]
    if asset_type:
        targets = [t for t in targets if asset_type.lower() in t.asset_types.lower()]
    if tech_tag:
        targets = [t for t in targets if tech_tag.lower() in t.tech_tags.lower()]

    return [_to_read(t) for t in targets]


@router.post("/", response_model=TargetRead)
def create_target(data: TargetCreate, db: Session = Depends(get_session)):
    t = Target(
        name=data.name,
        platform=data.platform,
        program_url=data.program_url,
        scope_count=data.scope_count,
        avg_payout=data.avg_payout,
        max_payout=data.max_payout,
        program_age_days=data.program_age_days,
        response_rating=data.response_rating,
        asset_types=json.dumps(data.asset_types),
        tech_tags=json.dumps(data.tech_tags),
        notes=data.notes,
    )
    t.priority_score = _compute_score(t)
    db.add(t)
    db.commit()
    db.refresh(t)
    return _to_read(t)


@router.post("/import-csv")
def import_csv(rows: list[TargetCreate], db: Session = Depends(get_session)):
    """Bulk import targets from CSV data (parsed on frontend)."""
    created = []
    for data in rows:
        t = Target(
            name=data.name,
            platform=data.platform,
            program_url=data.program_url,
            scope_count=data.scope_count,
            avg_payout=data.avg_payout,
            max_payout=data.max_payout,
            program_age_days=data.program_age_days,
            response_rating=data.response_rating,
            asset_types=json.dumps(data.asset_types),
            tech_tags=json.dumps(data.tech_tags),
            notes=data.notes,
        )
        t.priority_score = _compute_score(t)
        db.add(t)
        created.append(t)
    db.commit()
    return {"ok": True, "imported": len(created)}


@router.put("/{target_id}", response_model=TargetRead)
def update_target(target_id: int, data: TargetCreate, db: Session = Depends(get_session)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(status_code=404, detail="Target not found.")
    for field, value in data.model_dump().items():
        if field in ("asset_types", "tech_tags"):
            setattr(t, field, json.dumps(value))
        else:
            setattr(t, field, value)
    t.priority_score = _compute_score(t)
    db.add(t)
    db.commit()
    db.refresh(t)
    return _to_read(t)


@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_session)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(status_code=404, detail="Target not found.")
    db.delete(t)
    db.commit()
    return {"ok": True}
