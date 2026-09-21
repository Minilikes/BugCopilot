"""Findings router — CRUD for vulnerability findings."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from backend.db import get_session
from backend.models.finding import Finding, FindingCreate, FindingUpdate, FindingRead

router = APIRouter()


def _to_read(f: Finding) -> FindingRead:
    return FindingRead(
        id=f.id,
        scope_id=f.scope_id,
        title=f.title,
        vuln_class=f.vuln_class,
        endpoint=f.endpoint,
        parameter=f.parameter,
        http_method=f.http_method,
        severity=f.severity,
        cvss_score=f.cvss_score,
        cvss_vector=f.cvss_vector,
        bounty_low=f.bounty_low,
        bounty_high=f.bounty_high,
        status=f.status,
        duplicate_risk=f.duplicate_risk,
        steps_to_reproduce=f.steps_to_reproduce,
        evidence=f.evidence,
        impact=f.impact,
        remediation=f.remediation,
        notes=f.notes,
        analysis_summary=f.analysis_summary,
        submitted_at=f.submitted_at,
        resolved_at=f.resolved_at,
        bounty_paid=f.bounty_paid,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


@router.get("/", response_model=list[FindingRead])
def list_findings(
    scope_id: int | None = None,
    status: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_session),
):
    stmt = select(Finding)
    if scope_id:
        stmt = stmt.where(Finding.scope_id == scope_id)
    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    stmt = stmt.order_by(Finding.created_at.desc())
    findings = db.exec(stmt).all()
    return [_to_read(f) for f in findings]


@router.get("/stats")
def get_stats(db: Session = Depends(get_session)):
    """Dashboard stats: counts by status, total bounty paid."""
    findings = db.exec(select(Finding)).all()
    stats = {
        "total": len(findings),
        "by_status": {},
        "by_severity": {},
        "total_bounty_paid": sum(f.bounty_paid for f in findings),
        "total_bounty_potential_low": sum(f.bounty_low for f in findings if f.status not in ("resolved", "paid")),
        "total_bounty_potential_high": sum(f.bounty_high for f in findings if f.status not in ("resolved", "paid")),
    }
    for f in findings:
        stats["by_status"][f.status] = stats["by_status"].get(f.status, 0) + 1
        stats["by_severity"][f.severity] = stats["by_severity"].get(f.severity, 0) + 1
    return stats


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, db: Session = Depends(get_session)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return _to_read(f)


@router.post("/", response_model=FindingRead)
def create_finding(data: FindingCreate, db: Session = Depends(get_session)):
    f = Finding(**data.model_dump())
    db.add(f)
    db.commit()
    db.refresh(f)
    return _to_read(f)


@router.put("/{finding_id}", response_model=FindingRead)
def update_finding(finding_id: int, data: FindingUpdate, db: Session = Depends(get_session)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(f, field, value)
    f.updated_at = datetime.utcnow()

    db.add(f)
    db.commit()
    db.refresh(f)
    return _to_read(f)


@router.delete("/{finding_id}")
def delete_finding(finding_id: int, db: Session = Depends(get_session)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    db.delete(f)
    db.commit()
    return {"ok": True}
