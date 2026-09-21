"""Recon module router — all steps are opt-in and scope-gated."""

import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlmodel import Session, select
from pydantic import BaseModel

from backend.db import get_session
from backend.models.scope import ScopeSession
from backend.models.recon import ReconResult, ReconResultRead
from backend.services import scope_guard as sg
from backend.services import recon_engine as engine
from backend.services.cve_lookup import lookup_tech_cves

router = APIRouter()


def _get_active_scope(db: Session) -> ScopeSession:
    stmt = select(ScopeSession).where(ScopeSession.is_active == True)
    scope = db.exec(stmt).first()
    if not scope:
        raise HTTPException(status_code=400, detail="No active scope session. Set up scope first.")
    if not scope.authorized:
        raise HTTPException(status_code=403, detail="Scope session is not authorized.")
    return scope


def _save_results(results: list[dict], scope_id: int, result_type: str, db: Session):
    for r in results:
        record = ReconResult(
            scope_id=scope_id,
            result_type=result_type,
            target=r.get("target", ""),
            title=r.get("title", ""),
            data=json.dumps(r.get("data", {})),
            score=r.get("score", 0),
            score_reason=r.get("score_reason", ""),
        )
        db.add(record)
    db.commit()


def _read_result(r: ReconResult) -> ReconResultRead:
    try:
        data = json.loads(r.data or "{}")
    except Exception:
        data = {}
    return ReconResultRead(
        id=r.id,
        scope_id=r.scope_id,
        result_type=r.result_type,
        target=r.target,
        title=r.title,
        data=data,
        score=r.score,
        score_reason=r.score_reason,
        created_at=r.created_at,
    )


# ── GET results ───────────────────────────────────────────────────────────────

@router.get("/results", response_model=list[ReconResultRead])
def get_results(
    result_type: str | None = None,
    min_score: int = 0,
    db: Session = Depends(get_session),
):
    scope = _get_active_scope(db)
    stmt = select(ReconResult).where(ReconResult.scope_id == scope.id)
    if result_type:
        stmt = stmt.where(ReconResult.result_type == result_type)
    if min_score > 0:
        stmt = stmt.where(ReconResult.score >= min_score)
    stmt = stmt.order_by(ReconResult.score.desc())
    results = db.exec(stmt).all()
    return [_read_result(r) for r in results]


@router.delete("/results")
def clear_results(db: Session = Depends(get_session)):
    scope = _get_active_scope(db)
    results = db.exec(select(ReconResult).where(ReconResult.scope_id == scope.id)).all()
    for r in results:
        db.delete(r)
    db.commit()
    return {"ok": True, "deleted": len(results)}


# ── Subdomain Enumeration ──────────────────────────────────────────────────────

@router.post("/subdomains")
async def run_subdomains(db: Session = Depends(get_session)):
    scope = _get_active_scope(db)
    if not scope.target_domain:
        raise HTTPException(status_code=400, detail="No target domain set in scope session.")

    guard = sg.build_guard_from_session(scope)
    results = await engine.enumerate_subdomains(scope.target_domain, guard)
    _save_results(results, scope.id, "subdomain", db)
    return {"ok": True, "count": len(results), "results": results}


# ── Tech Fingerprinting ────────────────────────────────────────────────────────

class UrlRequest(BaseModel):
    url: str


@router.post("/tech-stack")
async def run_tech_fingerprint(req: UrlRequest, db: Session = Depends(get_session)):
    scope = _get_active_scope(db)
    guard = sg.build_guard_from_session(scope)

    in_scope, reason = guard.is_in_scope(req.url)
    if not in_scope:
        raise HTTPException(status_code=403, detail=f"URL is out of scope: {reason}")

    result = await engine.fingerprint_tech(req.url)

    # Save each detected tech as a separate record
    for tech_name, tech_info in result.get("technologies", {}).items():
        _save_results([{
            "target": req.url,
            "title": f"Tech: {tech_name} {tech_info.get('version', '')}".strip(),
            "data": {"tech": tech_name, "version": tech_info.get("version", ""), "source": tech_info.get("source", "")},
            "score": 3,
            "score_reason": f"Detected via {tech_info.get('source', 'fingerprinting')}",
        }], scope.id, "tech", db)

    return {"ok": True, "result": result}


# ── JS File Parsing ────────────────────────────────────────────────────────────

class JsParseRequest(BaseModel):
    base_url: str
    js_urls: list[str]


@router.post("/js-parse")
async def run_js_parse(req: JsParseRequest, db: Session = Depends(get_session)):
    scope = _get_active_scope(db)
    guard = sg.build_guard_from_session(scope)

    in_scope, reason = guard.is_in_scope(req.base_url)
    if not in_scope:
        raise HTTPException(status_code=403, detail=f"URL is out of scope: {reason}")

    results = await engine.parse_js_files(req.base_url, req.js_urls, guard)

    for r in results:
        rtype = "js_secret" if r.get("data", {}).get("type") == "js_secret" else "js_endpoint"
        _save_results([r], scope.id, rtype, db)

    return {"ok": True, "count": len(results), "results": results}


# ── robots.txt + Sitemap ───────────────────────────────────────────────────────

@router.post("/crawl")
async def run_crawl(req: UrlRequest, db: Session = Depends(get_session)):
    scope = _get_active_scope(db)
    guard = sg.build_guard_from_session(scope)

    in_scope, reason = guard.is_in_scope(req.url)
    if not in_scope:
        raise HTTPException(status_code=403, detail=f"URL is out of scope: {reason}")

    results = await engine.crawl_robots_sitemap(req.url)
    _save_results(results, scope.id, "robots", db)
    return {"ok": True, "count": len(results), "results": results}


# ── Header & Cookie Checks ─────────────────────────────────────────────────────

@router.post("/headers")
async def run_headers(req: UrlRequest, db: Session = Depends(get_session)):
    scope = _get_active_scope(db)
    guard = sg.build_guard_from_session(scope)

    in_scope, reason = guard.is_in_scope(req.url)
    if not in_scope:
        raise HTTPException(status_code=403, detail=f"URL is out of scope: {reason}")

    results = await engine.check_headers_cookies(req.url)
    _save_results(results, scope.id, "header_issue", db)
    return {"ok": True, "count": len(results), "results": results}


# ── CVE Lookup ─────────────────────────────────────────────────────────────────

class CveRequest(BaseModel):
    tech_name: str
    version: str = ""


@router.post("/cve-lookup")
async def run_cve_lookup(req: CveRequest, db: Session = Depends(get_session)):
    scope = _get_active_scope(db)

    cves = await lookup_tech_cves(req.tech_name, req.version)

    if cves and "error" not in cves[0]:
        top = cves[0]
        score = min(int(top.get("cvss_score", 0)), 10)
        _save_results([{
            "target": f"{req.tech_name} {req.version}".strip(),
            "title": f"CVE: {top.get('cve_id', 'unknown')} ({req.tech_name})",
            "data": {"cves": cves, "tech": req.tech_name, "version": req.version},
            "score": score,
            "score_reason": f"Top CVE: {top.get('cve_id')} — CVSS {top.get('cvss_score')}",
        }], scope.id, "cve", db)

    return {"ok": True, "tech": req.tech_name, "version": req.version, "cves": cves}
