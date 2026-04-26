import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


def load_local_env() -> None:
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_local_env()

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_ML_MODEL_PATH = BASE_DIR / "model" / "scam_detector.joblib"
MAX_INPUT_CHARS = 2000
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
DEFAULT_XAI_MODEL = "grok-2-latest"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
ML_WEIGHT = 0.6
AI_WEIGHT = 0.4
_ML_MODEL: dict[str, Any] | None = None
_ML_LOAD_ATTEMPTED = False

SYSTEM_PROMPT = """
You are Gmail Scam Detector, an AI safety assistant for students and job seekers.
Analyze email text for internship scams, visa scams, phishing, impersonation,
fake job offers, payment requests, credential theft, suspicious links, urgency,
and social engineering.

Return only valid JSON with exactly this shape:
{
  "scam_score": 0-100,
  "confidence": 0-100,
  "risk_level": "low" | "medium" | "high",
  "suspicious_phrases": ["short exact phrases from the email"],
  "explanation": "one short sentence, maximum 22 words",
  "recommended_action": "one short action sentence, maximum 16 words"
}

Rules:
- scam_score must be an integer from 0 to 100.
- confidence must be an integer from 0 to 100 showing how certain you are.
- risk_level must be low for 0-39, medium for 40-70, and high for 71-100.
- suspicious_phrases must be an array of strings.
- Include at most 3 suspicious_phrases.
- explanation must be concise, plain, and not longer than 22 words.
- recommended_action must be practical and not longer than 16 words.
- If the email looks safe, use a low scam_score and explain why.
""".strip()


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1)
    ai_provider: str | None = None


class AnalyzeResponse(BaseModel):
    scam_score: int
    confidence: int
    risk_level: str
    suspicious_phrases: list[str]
    explanation: str
    recommended_action: str
    ml_score: int | None = None
    ai_score: int | None = None
    model_type: str | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Load the ML model during startup so the first real scan is faster.
    get_ml_model()
    yield


app = FastAPI(title="Gmail Scam Detector API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def normalize_result(raw: dict[str, Any]) -> AnalyzeResponse:
    score = raw.get("scam_score", 0)
    confidence = raw.get("confidence", 75)
    risk_level = str(raw.get("risk_level", "")).lower().strip()
    phrases = raw.get("suspicious_phrases", [])
    explanation = raw.get("explanation", "")
    recommended_action = raw.get("recommended_action", "")
    ml_score = raw.get("ml_score")
    ai_score = raw.get("ai_score")
    model_type = raw.get("model_type")

    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0

    try:
        confidence = int(confidence)
    except (TypeError, ValueError):
        confidence = 75

    score = max(0, min(100, score))
    confidence = max(0, min(100, confidence))

    if risk_level not in {"low", "medium", "high"}:
        if score > 70:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"

    if not isinstance(phrases, list):
        phrases = []

    phrases = [str(phrase)[:100] for phrase in phrases if str(phrase).strip()][:3]
    explanation = str(explanation).strip()[:180]
    recommended_action = str(recommended_action).strip()[:140]

    try:
        ml_score = None if ml_score is None else max(0, min(100, int(ml_score)))
    except (TypeError, ValueError):
        ml_score = None

    try:
        ai_score = None if ai_score is None else max(0, min(100, int(ai_score)))
    except (TypeError, ValueError):
        ai_score = None

    return AnalyzeResponse(
        scam_score=score,
        confidence=confidence,
        risk_level=risk_level,
        suspicious_phrases=phrases,
        explanation=explanation or "No major scam signals found.",
        recommended_action=recommended_action or "Verify links and sender before acting.",
        ml_score=ml_score,
        ai_score=ai_score,
        model_type=str(model_type)[:80] if model_type else None,
    )


def risk_level_from_score(score: int) -> str:
    if score > 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def get_ml_model() -> dict[str, Any] | None:
    global _ML_LOAD_ATTEMPTED, _ML_MODEL

    if _ML_LOAD_ATTEMPTED:
        return _ML_MODEL

    _ML_LOAD_ATTEMPTED = True
    model_path = Path(os.getenv("ML_MODEL_PATH", str(DEFAULT_ML_MODEL_PATH)))
    if not model_path.exists():
        return None

    try:
        import joblib

        loaded = joblib.load(model_path)
        if isinstance(loaded, dict) and "pipeline" in loaded:
            _ML_MODEL = loaded
        else:
            _ML_MODEL = {"pipeline": loaded, "model_type": "unknown"}
    except Exception as exc:
        print(f"Could not load ML model from {model_path}: {exc}")
        _ML_MODEL = None

    return _ML_MODEL


# ------------------------------------------------------------------
#  Fix: Reformat text to match the training format (adds URLs line)
# ------------------------------------------------------------------
def reformat_for_ml(email_text: str) -> str:
    """Make the extension's text match training format (includes URLs line)."""
    # Extract all URLs from the text
    urls = re.findall(r'https?://\S+', email_text)
    urls_line = "URLs: " + " ".join(urls) if urls else "URLs:"

    # The extension text typically has Subject, Sender, blank line, then body.
    # Insert URLs line right after the blank line.
    parts = email_text.split('\n\n', 1)
    if len(parts) == 2:
        return parts[0] + '\n' + urls_line + '\n\n' + parts[1]
    else:
        # Fallback: just prepend URLs line
        return urls_line + '\n\n' + email_text


def predict_ml_score(email_text: str) -> tuple[int | None, str | None]:
    model = get_ml_model()
    if not model:
        return None, None

    pipeline = model["pipeline"]
    # Format input to match training data
    formatted_text = reformat_for_ml(email_text)
    probability = pipeline.predict_proba([formatted_text])[0][1]
    score = int(round(float(probability) * 100))
    return max(0, min(100, score)), str(model.get("model_type") or "tfidf_logistic_regression")


def blend_ml_and_ai(ml_score: int | None, ai_result: AnalyzeResponse) -> AnalyzeResponse:
    if ml_score is None:
        ai_result.ai_score = ai_result.scam_score
        return ai_result

    ai_score = ai_result.scam_score
    final_score = int(round((ML_WEIGHT * ml_score) + (AI_WEIGHT * ai_score)))
    agreement = 100 - abs(ml_score - ai_score)
    confidence = int(round((ai_result.confidence * 0.5) + (agreement * 0.5)))

    ai_result.ai_score = ai_score
    ai_result.ml_score = ml_score
    ai_result.scam_score = max(0, min(100, final_score))
    ai_result.confidence = max(0, min(100, confidence))
    ai_result.risk_level = risk_level_from_score(ai_result.scam_score)
    return ai_result


def post_json(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(
            status_code=502,
            detail=f"AI provider API error: {detail}",
        ) from exc
    except urllib.error.URLError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach AI provider API: {exc.reason}",
        ) from exc


def parse_json_text(text: str) -> AnalyzeResponse:
    return normalize_result(json.loads(text or "{}"))


def analyze_with_openai_compatible(
    *,
    api_key: str,
    base_url: str,
    model: str,
    email_text: str,
) -> AnalyzeResponse:
    response_data = post_json(
        f"{base_url.rstrip('/')}/chat/completions",
        {"Authorization": f"Bearer {api_key}"},
        {
            "model": model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Analyze this email:\n\n{email_text}",
                },
            ],
        },
    )

    try:
        content = response_data["choices"][0]["message"].get("content") or "{}"
    except (KeyError, IndexError, TypeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="AI provider returned an unexpected response shape.",
        ) from exc

    return parse_json_text(content)


def analyze_with_gemini(api_key: str, email_text: str) -> AnalyzeResponse:
    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    response_data = post_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        {"x-goog-api-key": api_key},
        {
            "systemInstruction": {
                "parts": [{"text": SYSTEM_PROMPT}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"Analyze this email:\n\n{email_text}"}],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        },
    )

    try:
        content = response_data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Gemini returned an unexpected response shape.",
        ) from exc

    return parse_json_text(content)


def choose_provider(requested_provider: str | None = None) -> str:
    requested = (requested_provider or os.getenv("AI_PROVIDER", "auto")).strip().lower()
    if requested != "auto":
        return requested

    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    if os.getenv("GROQ_API_KEY"):
        return "groq"
    if os.getenv("XAI_API_KEY"):
        return "xai"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return "none"


@app.get("/")
def health_check() -> dict[str, str | bool]:
    return {
        "status": "Gmail Scam Detector API is running",
        "provider": choose_provider(),
        "ml_model_loaded": get_ml_model() is not None,
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(payload: AnalyzeRequest) -> AnalyzeResponse:
    email_text = payload.text.strip()[:MAX_INPUT_CHARS]
    if not email_text:
        raise HTTPException(status_code=400, detail="Text cannot be empty.")

    provider = choose_provider(payload.ai_provider)
    ml_score, model_type = predict_ml_score(email_text)

    try:
        ai_result: AnalyzeResponse
        if provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise HTTPException(status_code=500, detail="GEMINI_API_KEY is missing.")
            ai_result = analyze_with_gemini(api_key, email_text)
            ai_result.model_type = model_type
            return blend_ml_and_ai(ml_score, ai_result)

        if provider == "groq":
            api_key = os.getenv("GROQ_API_KEY")
            if not api_key:
                raise HTTPException(status_code=500, detail="GROQ_API_KEY is missing.")
            ai_result = analyze_with_openai_compatible(
                api_key=api_key,
                base_url="https://api.groq.com/openai/v1",
                model=os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL),
                email_text=email_text,
            )
            ai_result.model_type = model_type
            return blend_ml_and_ai(ml_score, ai_result)

        if provider == "xai":
            api_key = os.getenv("XAI_API_KEY")
            if not api_key:
                raise HTTPException(status_code=500, detail="XAI_API_KEY is missing.")
            ai_result = analyze_with_openai_compatible(
                api_key=api_key,
                base_url="https://api.x.ai/v1",
                model=os.getenv("XAI_MODEL", DEFAULT_XAI_MODEL),
                email_text=email_text,
            )
            ai_result.model_type = model_type
            return blend_ml_and_ai(ml_score, ai_result)

        if provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise HTTPException(status_code=500, detail="OPENAI_API_KEY is missing.")
            ai_result = analyze_with_openai_compatible(
                api_key=api_key,
                base_url="https://api.openai.com/v1",
                model=os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL),
                email_text=email_text,
            )
            ai_result.model_type = model_type
            return blend_ml_and_ai(ml_score, ai_result)

        # If provider not recognized and no AI keys set, fallback to ML only
        if ml_score is not None:
            return AnalyzeResponse(
                scam_score=ml_score,
                confidence=80,
                risk_level=risk_level_from_score(ml_score),
                suspicious_phrases=[],
                explanation="ML model completed the scan; AI explanation is unavailable.",
                recommended_action="Use caution and verify sender details.",
                ml_score=ml_score,
                ai_score=None,
                model_type=model_type,
            )

        raise HTTPException(
            status_code=500,
            detail="Set GEMINI_API_KEY, GROQ_API_KEY, or XAI_API_KEY on the server.",
        )

    except HTTPException:
        # If AI fails but ML exists, return ML-only result
        if ml_score is not None:
            return AnalyzeResponse(
                scam_score=ml_score,
                confidence=78,
                risk_level=risk_level_from_score(ml_score),
                suspicious_phrases=[],
                explanation="ML model completed the scan; AI provider was unavailable.",
                recommended_action="Verify links and sender before acting.",
                ml_score=ml_score,
                ai_score=None,
                model_type=model_type,
            )
        raise

    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail="Model returned invalid JSON.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Analysis failed: {exc}",
        ) from exc


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.getenv("PORT", "8000")),
        http="h11",
        loop="asyncio",
    )
