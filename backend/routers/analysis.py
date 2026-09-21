"""Interactive Analysis router — LLM-powered chat for vulnerability assessment."""

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from pydantic import BaseModel

from backend.db import get_session
from backend.models.scope import ScopeSession
from backend.services import llm_client

router = APIRouter()


def _get_active_scope_context(db: Session) -> str:
    stmt = select(ScopeSession).where(ScopeSession.is_active == True)
    scope = db.exec(stmt).first()
    if not scope:
        return "No active scope session."
    return (
        f"Program: {scope.program_name} ({scope.platform}), "
        f"Target domain: {scope.target_domain}, "
        f"Authorization: confirmed={scope.authorized}"
    )


class AnalyzeRequest(BaseModel):
    content: str
    learn_mode: bool = False
    conversation_history: list[dict] = []


class ChatRequest(BaseModel):
    messages: list[dict]  # [{role: "user"|"assistant", content: "..."}]


@router.post("/analyze")
async def analyze(req: AnalyzeRequest, db: Session = Depends(get_session)):
    """
    Main analysis endpoint — takes a raw HTTP request/response, parameter description,
    or observation and returns structured vulnerability assessment.
    """
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty.")

    scope_context = _get_active_scope_context(db)
    result = await llm_client.analyze(
        content=req.content,
        scope_context=scope_context,
        learn_mode=req.learn_mode,
        conversation_history=req.conversation_history,
    )
    return result


@router.post("/chat")
async def chat(req: ChatRequest, db: Session = Depends(get_session)):
    """Free-form follow-up chat with the analysis assistant."""
    if not req.messages:
        raise HTTPException(status_code=400, detail="Messages cannot be empty.")

    # Inject scope context as system-level context
    scope_context = _get_active_scope_context(db)
    messages = [
        {"role": "system", "content": f"Active scope: {scope_context}"},
        *req.messages,
    ]

    response = await llm_client.chat_freeform(messages)
    return {"response": response}


@router.get("/status")
def analysis_status():
    """Check if LLM is configured."""
    from backend import config
    configured = bool(config.LLM_API_KEY and config.LLM_API_KEY != "sk-...")
    return {
        "configured": configured,
        "model": config.LLM_MODEL,
        "base_url": config.LLM_BASE_URL,
    }
