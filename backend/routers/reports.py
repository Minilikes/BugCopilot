"""Report generation router."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlmodel import Session

from backend.db import get_session
from backend.models.finding import Finding
from backend.routers.findings import _to_read
from backend.services.report_templates import generate_report
from backend.services.cvss import CVSSMetrics, calculate_cvss, vector_string, parse_vector, estimate_bounty
from pydantic import BaseModel

router = APIRouter()


@router.get("/{finding_id}")
def get_report(
    finding_id: int,
    platform: str = "generic",
    db: Session = Depends(get_session),
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding_read = _to_read(f)
    report = generate_report(finding_read, platform)
    return {"report": report, "platform": platform}


class CVSSRequest(BaseModel):
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "N"
    I: str = "N"
    A: str = "N"


@router.post("/cvss/calculate")
def calculate(req: CVSSRequest):
    """Calculate CVSS 3.1 base score from metric values."""
    m = CVSSMetrics(
        AV=req.AV, AC=req.AC, PR=req.PR, UI=req.UI,
        S=req.S, C=req.C, I=req.I, A=req.A,
    )
    score, severity = calculate_cvss(m)
    vec = vector_string(m)
    bounty_low, bounty_high = estimate_bounty(severity)
    return {
        "score": score,
        "severity": severity,
        "vector": vec,
        "bounty_low": bounty_low,
        "bounty_high": bounty_high,
    }


@router.post("/cvss/parse")
def parse(vector: str):
    """Parse a CVSS 3.x vector string into metrics."""
    m = parse_vector(vector)
    if not m:
        raise HTTPException(status_code=400, detail="Invalid CVSS vector string.")
    score, severity = calculate_cvss(m)
    return {
        "metrics": {"AV": m.AV, "AC": m.AC, "PR": m.PR, "UI": m.UI, "S": m.S, "C": m.C, "I": m.I, "A": m.A},
        "score": score,
        "severity": severity,
    }
