"""Disclosure timeline router."""

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from backend.db import get_session
from backend.models.recon import TimelineEntry, TimelineEntryCreate, TimelineEntryRead

router = APIRouter()

# Typical platform SLAs (days)
PLATFORM_SLAS = {
    "HackerOne": {"triage": 5, "resolution": 90, "escalation": 14},
    "Bugcrowd": {"triage": 7, "resolution": 90, "escalation": 21},
    "Intigriti": {"triage": 5, "resolution": 90, "escalation": 14},
    "Other": {"triage": 7, "resolution": 90, "escalation": 21},
}


def _to_read(e: TimelineEntry) -> TimelineEntryRead:
    return TimelineEntryRead(
        id=e.id,
        finding_id=e.finding_id,
        event_type=e.event_type,
        event_date=e.event_date,
        notes=e.notes,
        created_at=e.created_at,
    )


@router.get("/{finding_id}", response_model=list[TimelineEntryRead])
def get_timeline(finding_id: int, db: Session = Depends(get_session)):
    entries = db.exec(
        select(TimelineEntry)
        .where(TimelineEntry.finding_id == finding_id)
        .order_by(TimelineEntry.event_date)
    ).all()
    return [_to_read(e) for e in entries]


@router.post("/{finding_id}", response_model=TimelineEntryRead)
def add_timeline_entry(
    finding_id: int,
    data: TimelineEntryCreate,
    db: Session = Depends(get_session),
):
    entry = TimelineEntry(
        finding_id=finding_id,
        event_type=data.event_type,
        event_date=data.event_date,
        notes=data.notes,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return _to_read(entry)


@router.delete("/entry/{entry_id}")
def delete_entry(entry_id: int, db: Session = Depends(get_session)):
    e = db.get(TimelineEntry, entry_id)
    if not e:
        raise HTTPException(status_code=404, detail="Entry not found.")
    db.delete(e)
    db.commit()
    return {"ok": True}


@router.get("/{finding_id}/sla")
def get_sla(finding_id: int, platform: str = "HackerOne", db: Session = Depends(get_session)):
    """Compute SLA deadlines based on submission date."""
    entries = db.exec(
        select(TimelineEntry)
        .where(TimelineEntry.finding_id == finding_id)
        .where(TimelineEntry.event_type == "submitted")
        .order_by(TimelineEntry.event_date)
    ).all()

    if not entries:
        return {"message": "No submission event found. Add a 'submitted' timeline entry first."}

    submitted_date = entries[0].event_date
    sla = PLATFORM_SLAS.get(platform, PLATFORM_SLAS["Other"])

    now = datetime.utcnow()
    triage_deadline = submitted_date + timedelta(days=sla["triage"])
    escalation_deadline = submitted_date + timedelta(days=sla["escalation"])
    resolution_deadline = submitted_date + timedelta(days=sla["resolution"])

    def status(deadline):
        if now > deadline:
            return "overdue"
        elif (deadline - now).days <= 3:
            return "due_soon"
        return "on_track"

    return {
        "submitted_at": submitted_date,
        "platform": platform,
        "deadlines": {
            "triage": {"date": triage_deadline, "status": status(triage_deadline)},
            "escalation": {"date": escalation_deadline, "status": status(escalation_deadline)},
            "resolution": {"date": resolution_deadline, "status": status(resolution_deadline)},
        },
        "days_since_submission": (now - submitted_date).days,
    }
