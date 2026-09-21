"""LLM client — calls OpenAI-compatible API for analysis chat."""

import json
import asyncio
from openai import AsyncOpenAI
from backend import config

SYSTEM_PROMPT = """You are BugCopilot, an AI assistant exclusively for AUTHORIZED bug bounty researchers.

Your role:
1. Analyze HTTP requests/responses, parameters, and observations for potential security vulnerabilities
2. Assess plausibility: explain whether the finding looks exploitable and why, with technical reasoning
3. Suggest SAFE, NON-DESTRUCTIVE next verification steps (e.g., basic reflection checks, benign parameter variations)
4. Flag likely-duplicate or low-value findings early to save the researcher time
5. Estimate severity (CVSS 3.1 range) and realistic bounty tier based on program context
6. In Learn Mode: also explain the root cause and vulnerability class clearly for educational value

STRICT CONSTRAINTS:
- NEVER suggest brute-force attacks, DoS, or destructive actions
- NEVER suggest payloads that could cause data loss or service disruption
- NEVER suggest bypassing authentication in ways that could access real user data
- ALWAYS frame suggestions as "safe verification" steps, not exploitation
- ALWAYS remind the researcher to stay within their authorized scope
- If asked to do something outside these constraints, politely decline and redirect

RESPONSE FORMAT:
You MUST respond with valid JSON in this exact structure:
{
  "plausibility": "high|medium|low|unlikely",
  "plausibility_reasoning": "technical explanation of why/why not",
  "vulnerability_class": "XSS|IDOR|SQLi|SSRF|Auth Bypass|Info Disclosure|CORS|Other|Unknown",
  "next_steps": [
    {"step": "description of safe verification step", "safe": true, "rationale": "why this helps confirm"}
  ],
  "duplicate_risk": "low|medium|high",
  "duplicate_notes": "explanation of why this might be a known/reported issue",
  "severity_estimate": "Critical|High|Medium|Low|Informational",
  "cvss_range": "e.g., 6.5-7.8",
  "bounty_tier": "e.g., $500-$2000 (Medium tier)",
  "learn_mode_explanation": "only if learn_mode is true — explain the vuln root cause and defensive mitigation",
  "summary": "one-sentence triage summary"
}
"""


def _build_user_message(content: str, scope_context: str, learn_mode: bool) -> str:
    parts = [f"**Scope context:** {scope_context}\n" if scope_context else ""]
    parts.append(f"**Learn Mode:** {'ON' if learn_mode else 'OFF'}\n\n")
    parts.append("**Researcher's input:**\n")
    parts.append(content)
    return "".join(parts)


async def analyze(
    content: str,
    scope_context: str = "",
    learn_mode: bool = False,
    conversation_history: list[dict] | None = None,
) -> dict:
    """
    Send content to LLM for vulnerability analysis.
    Returns structured analysis dict.
    """
    if not config.LLM_API_KEY:
        return {
            "error": "LLM API key not configured. Add LLM_API_KEY to your .env file.",
            "plausibility": "unknown",
            "summary": "LLM not configured.",
        }

    client = AsyncOpenAI(
        api_key=config.LLM_API_KEY,
        base_url=config.LLM_BASE_URL,
    )

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Include conversation history for multi-turn context
    if conversation_history:
        messages.extend(conversation_history[-6:])  # Last 3 exchanges

    messages.append({
        "role": "user",
        "content": _build_user_message(content, scope_context, learn_mode),
    })

    try:
        response = await client.chat.completions.create(
            model=config.LLM_MODEL,
            messages=messages,
            temperature=0.3,
            max_tokens=2000,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content or "{}"
        result = json.loads(raw)
        result["raw_response"] = raw
        return result
    except json.JSONDecodeError as e:
        return {"error": f"LLM returned invalid JSON: {e}", "raw_response": raw}
    except Exception as e:
        return {"error": str(e)}


async def chat_freeform(messages: list[dict]) -> str:
    """
    Free-form chat (for general Q&A or follow-up questions).
    Returns plain text response.
    """
    if not config.LLM_API_KEY:
        return "LLM API key not configured. Add LLM_API_KEY to your .env file."

    client = AsyncOpenAI(
        api_key=config.LLM_API_KEY,
        base_url=config.LLM_BASE_URL,
    )

    sys_msgs = [{"role": "system", "content": SYSTEM_PROMPT}]

    try:
        response = await client.chat.completions.create(
            model=config.LLM_MODEL,
            messages=sys_msgs + messages,
            temperature=0.4,
            max_tokens=1500,
        )
        return response.choices[0].message.content or ""
    except Exception as e:
        return f"Error: {e}"
