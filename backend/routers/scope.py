"""Scope Gate router — manages authorization sessions."""

import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from backend.db import get_session
from backend.models.scope import ScopeSession, ScopeSessionCreate, ScopeSessionRead

router = APIRouter()


def _parse_patterns(session: ScopeSession) -> ScopeSessionRead:
    return ScopeSessionRead(
        id=session.id,
        program_name=session.program_name,
        platform=session.platform,
        scope_url=session.scope_url,
        authorized=session.authorized,
        auth_note=session.auth_note,
        in_scope_patterns=json.loads(session.in_scope_patterns or "[]"),
        out_scope_patterns=json.loads(session.out_scope_patterns or "[]"),
        target_domain=session.target_domain,
        is_active=session.is_active,
        created_at=session.created_at,
    )


@router.get("/active", response_model=ScopeSessionRead | None)
def get_active_scope(db: Session = Depends(get_session)):
    """Return the currently active scope session, or null."""
    stmt = select(ScopeSession).where(ScopeSession.is_active == True).order_by(ScopeSession.id.desc())
    session = db.exec(stmt).first()
    return _parse_patterns(session) if session else None


@router.get("/", response_model=list[ScopeSessionRead])
def list_scopes(db: Session = Depends(get_session)):
    """List all scope sessions."""
    sessions = db.exec(select(ScopeSession).order_by(ScopeSession.id.desc())).all()
    return [_parse_patterns(s) for s in sessions]


@router.post("/", response_model=ScopeSessionRead)
def create_scope(data: ScopeSessionCreate, db: Session = Depends(get_session)):
    """Create a new scope session. Authorization must be confirmed."""
    if not data.authorized:
        raise HTTPException(
            status_code=400,
            detail="Authorization must be confirmed before creating a scope session.",
        )
    if not data.program_name:
        raise HTTPException(status_code=400, detail="Program name is required.")

    # Deactivate any currently active sessions
    active = db.exec(select(ScopeSession).where(ScopeSession.is_active == True)).all()
    for s in active:
        s.is_active = False
        db.add(s)

    session = ScopeSession(
        program_name=data.program_name,
        platform=data.platform,
        scope_url=data.scope_url,
        authorized=data.authorized,
        auth_note=data.auth_note,
        in_scope_patterns=json.dumps(data.in_scope_patterns),
        out_scope_patterns=json.dumps(data.out_scope_patterns),
        target_domain=data.target_domain,
        is_active=True,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return _parse_patterns(session)


@router.delete("/{scope_id}")
def delete_scope(scope_id: int, db: Session = Depends(get_session)):
    """Delete a scope session."""
    session = db.get(ScopeSession, scope_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scope session not found.")
    db.delete(session)
    db.commit()
    return {"ok": True}


@router.post("/{scope_id}/activate")
def activate_scope(scope_id: int, db: Session = Depends(get_session)):
    """Make a scope session the active one."""
    target = db.get(ScopeSession, scope_id)
    if not target:
        raise HTTPException(status_code=404, detail="Scope session not found.")

    # Deactivate others
    active = db.exec(select(ScopeSession).where(ScopeSession.is_active == True)).all()
    for s in active:
        s.is_active = False
        db.add(s)

    target.is_active = True
    db.add(target)
    db.commit()
    return {"ok": True, "active_scope_id": scope_id}
