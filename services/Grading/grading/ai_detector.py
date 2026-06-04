"""
ai_detector.py
==============
Two-layer AI detection:

Layer 1 — RoBERTa (fairmark_ai_detector):
  - Runs on raw text (no enrichment — model trained on raw text)
  - Good at detecting long formal AI-generated text

Layer 2 — Gemini safety net:
  - Catches short formal AI answers that RoBERTa misses
  - Uses structured scoring rubric for consistency

Rules:
  - Only checks: essay and short_answer types
  - Skips single-word answers (true/false/single letter)
  - Skips answers under 20 words (too short to detect reliably)
  - If RoBERTa >= 0.85 AND answer >= 50 words → auto-reject (skip Gemini)
  - If Gemini >= 0.85 → auto-reject
  - Otherwise: weighted score = (RoBERTa * 0.30) + (Gemini * 0.70)
  - If weighted >= 0.55 → rejected
"""

import re
import json
import time
import logging
import requests
import os
import torch
import google.generativeai as genai
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logger = logging.getLogger(__name__)

# ===== Config =====
AI_THRESHOLD      = float(os.getenv("AI_THRESHOLD", "0.55"))
AUTO_REJECT_SCORE = float(os.getenv("AI_AUTO_REJECT_SCORE", "0.85"))
GEMINI_WEIGHT     = float(os.getenv("GEMINI_WEIGHT", "0.70"))
ROBERTA_WEIGHT    = float(os.getenv("ROBERTA_WEIGHT", "0.30"))
DETECTOR_API_URL  = os.getenv("AI_DETECTION_URL", "http://127.0.0.1:5000/predict")
GEMINI_DELAY      = float(os.getenv("GEMINI_DELAY", "0"))
AI_CHECK_TYPES    = {"essay", "short_answer"}
MIN_WORDS         = 20   # skip detection for answers shorter than this

# ===== Find model path relative to this file =====
_THIS_DIR  = Path(__file__).resolve().parent
MODEL_PATH = os.getenv("AI_MODEL_PATH", str(_THIS_DIR / "fairmark_ai_detector"))

if not Path(MODEL_PATH).exists():
    MODEL_PATH = str(_THIS_DIR.parent / "fairmark_ai_detector")
if not Path(MODEL_PATH).exists():
    MODEL_PATH = str(Path.cwd() / "fairmark_ai_detector")

logger.info(f"AI detector model path: {MODEL_PATH} | exists: {Path(MODEL_PATH).exists()}")

# ===== RoBERTa model (loaded once) =====
_tokenizer = None
_model     = None
_device    = None


def _load_model():
    global _tokenizer, _model, _device
    if _model is None:
        logger.info("Loading FairMark AI detector model...")
        _device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        _model     = AutoModelForSequenceClassification.from_pretrained(
            MODEL_PATH,
            ignore_mismatched_sizes=True
        )
        _model.to(_device)
        _model.eval()
        logger.info(f"AI detector loaded on {_device} ✅")


# ===== ROBERTA DETECTION =====

def detect_via_api(text: str) -> dict:
    """Call the running detector Flask API on port 5002."""
    try:
        r = requests.post(DETECTOR_API_URL, json={"text": text}, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        raise ConnectionError(f"Detector API not reachable at {DETECTOR_API_URL}")
    except Exception as e:
        raise RuntimeError(f"Detector API error: {e}")


def detect_via_model(text: str) -> dict:
    """Run RoBERTa detection directly on raw text."""
    _load_model()

    # Use raw text — no enrichment (model was trained on raw text)
    inputs = _tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512
    ).to(_device)

    with torch.no_grad():
        outputs = _model(**inputs)

    probs      = torch.softmax(outputs.logits, dim=1)
    human_prob = probs[0][0].item() * 100
    ai_prob    = probs[0][1].item() * 100

    return {
        "human_percentage": round(human_prob, 2),
        "ai_percentage":    round(ai_prob, 2),
        "decision":         "rejected" if (ai_prob / 100) >= AI_THRESHOLD else "accepted"
    }


# ===== GEMINI DETECTION =====

def detect_via_gemini(text: str, question_text: str = "") -> dict:
    """
    Deterministic Gemini detection with structured scoring rubric.
    """
    prompt = f"""
You are a strict AI-text detector for university exam answers.
Score how likely this answer was AI-generated using the rubric below.

Question: {question_text or "Not provided"}
Student Answer: \"\"\"{text}\"\"\"

SCORING RUBRIC:
Score 0.85-1.00 if ALL of:
  - Perfect grammar with zero errors
  - Comprehensively covers ALL aspects of the question
  - Uses multiple formal AI phrases ("furthermore", "it is worth noting", etc.)
  - Reads exactly like a textbook entry

Score 0.65-0.84 if MOST of:
  - Mostly perfect grammar
  - Covers topic well but not exhaustively
  - Some formal phrasing but not excessive
  - Well-structured beyond what's expected under exam conditions

Score 0.40-0.64 if MIXED:
  - Mix of formal and informal language
  - Covers some aspects but misses others
  - Occasional grammar issues
  - Somewhat structured

Score 0.00-0.39 if HUMAN indicators dominate:
  - Casual language, abbreviations (&, bc, w/, ->)
  - Clear knowledge gaps or partial answers
  - Natural grammar errors or missing articles
  - Short direct answer without elaborate structure
  - Math notation or calculations written naturally
  - Starts with question label (a), b), etc.)
  - Missing capitalization at start of sentences

Return ONLY valid JSON:
{{
  "ai_probability": <number 0.0-1.0>,
  "reasoning": "<one sentence>"
}}
"""
    try:
        time.sleep(GEMINI_DELAY)
        gemini_model = genai.GenerativeModel("gemini-2.5-flash")
        response     = gemini_model.generate_content(prompt)
        text_resp    = response.text.strip()
        text_resp    = re.sub(r"```(?:json)?", "", text_resp).replace("```", "").strip()

        result  = json.loads(text_resp)
        ai_prob = float(result.get("ai_probability", 0.0))
        ai_prob = max(0.0, min(1.0, ai_prob))

        return {
            "ai_percentage":    round(ai_prob * 100, 2),
            "human_percentage": round((1 - ai_prob) * 100, 2),
            "decision":         "rejected" if ai_prob >= AI_THRESHOLD else "accepted",
            "reasoning":        result.get("reasoning", "")
        }
    except Exception as e:
        logger.warning(f"Gemini detection failed: {e}")
        return {
            "ai_percentage":    0.0,
            "human_percentage": 100.0,
            "decision":         "accepted",
            "reasoning":        f"Gemini detection failed: {e}"
        }


# ===== MAIN CHECK FUNCTION =====

def check_answer(text: str, use_api: bool = False, question_text: str = "") -> dict:
    """
    Two-layer AI detection.
    Skips detection for:
      - Empty/unanswered
      - Single-word T/F answers (true/false/t/f)
      - Answers under MIN_WORDS words
    """
    # ── Skip conditions ────────────────────────────────────────
    if not text or text.strip() in ("na", "unclear", ""):
        return _clean_result()

    text_stripped = text.strip().lower()

    # Skip single-word T/F answers
    normalized = re.sub(r"[^a-z]", "", text.lower())

    if normalized in ("true", "false", "t", "f", "a", "b", "c", "d"):
        return _clean_result()

    # Skip very short answers (under MIN_WORDS words)
    word_count = len(text.split())
    if word_count < MIN_WORDS:
        logger.info(f"AI detection skipped — answer too short ({word_count} words < {MIN_WORDS})")
        return _clean_result()

    # ── Step 1: RoBERTa ───────────────────────────────────────
    roberta_result  = None
    roberta_ai_prob = 0.0

    try:
        if use_api:
            roberta_result = detect_via_api(text)
        else:
            roberta_result = detect_via_model(text)
        roberta_ai_prob = roberta_result.get("ai_percentage", 0.0) / 100
    except Exception as e:
        logger.warning(f"RoBERTa detection failed: {e}")

    # Auto-reject if RoBERTa very confident on longer answers only
    if roberta_ai_prob >= AUTO_REJECT_SCORE and word_count >= 50:
        logger.info(f"AI Detection — RoBERTa auto-reject ({roberta_ai_prob*100:.1f}%)")
        return {
            "ai_percentage":    round(roberta_ai_prob * 100, 2),
            "human_percentage": round((1 - roberta_ai_prob) * 100, 2),
            "decision":         "rejected",
            "is_ai":            True,
            "flagged":          True,
            "flagged_by":       ["RoBERTa"],
            "weighted_score":   round(roberta_ai_prob, 4),
            "roberta_result":   {"ai_percentage": round(roberta_ai_prob * 100, 2)},
            "gemini_result":    None
        }
    # short answers always fall through to Gemini regardless of RoBERTa confidence

    # ── Step 2: Gemini safety net ─────────────────────────────
    gemini_result  = detect_via_gemini(text, question_text)
    gemini_ai_prob = gemini_result.get("ai_percentage", 0.0) / 100

    # Auto-reject if Gemini very confident
    if gemini_ai_prob >= AUTO_REJECT_SCORE:
        logger.info(f"AI Detection — Gemini auto-reject ({gemini_ai_prob*100:.1f}%)")
        return {
            "ai_percentage":    round(gemini_ai_prob * 100, 2),
            "human_percentage": round((1 - gemini_ai_prob) * 100, 2),
            "decision":         "rejected",
            "is_ai":            True,
            "flagged":          True,
            "flagged_by":       ["Gemini"],
            "weighted_score":   round(gemini_ai_prob, 4),
            "roberta_result":   {"ai_percentage": round(roberta_ai_prob * 100, 2)} if roberta_result else None,
            "gemini_result":    {
                "ai_percentage": gemini_result.get("ai_percentage", 0.0),
                "reasoning":     gemini_result.get("reasoning", "")
            }
        }

    # ── Step 3: Weighted score ────────────────────────────────
    weighted = (roberta_ai_prob * ROBERTA_WEIGHT) + (gemini_ai_prob * GEMINI_WEIGHT)
    is_ai    = weighted >= AI_THRESHOLD

    flagged_by = []
    if roberta_ai_prob >= AI_THRESHOLD:
        flagged_by.append("RoBERTa")
    if gemini_ai_prob >= AI_THRESHOLD:
        flagged_by.append("Gemini")
    if is_ai and not flagged_by:
        flagged_by.append("weighted-score")

    final_ai_pct = round(weighted * 100, 2)

    logger.info(
        f"AI Detection — RoBERTa: {roberta_ai_prob*100:.1f}% | "
        f"Gemini: {gemini_ai_prob*100:.1f}% | "
        f"Weighted: {final_ai_pct:.1f}% | "
        f"{'FLAGGED by ' + '+'.join(flagged_by) if is_ai else 'CLEAN'}"
    )

    return {
        "ai_percentage":    final_ai_pct,
        "human_percentage": round(100 - final_ai_pct, 2),
        "decision":         "rejected" if is_ai else "accepted",
        "is_ai":            is_ai,
        "flagged":          is_ai,
        "flagged_by":       flagged_by,
        "weighted_score":   round(weighted, 4),
        "roberta_result":   {
            "ai_percentage": round(roberta_ai_prob * 100, 2)
        } if roberta_result else None,
        "gemini_result":    {
            "ai_percentage": gemini_result.get("ai_percentage", 0.0),
            "reasoning":     gemini_result.get("reasoning", "")
        }
    }


def _clean_result() -> dict:
    """Return a clean accepted result — used for skipped detection."""
    return {
        "ai_percentage":    0.0,
        "human_percentage": 100.0,
        "decision":         "accepted",
        "is_ai":            False,
        "flagged":          False,
        "flagged_by":       [],
        "roberta_result":   None,
        "gemini_result":    None
    }


def should_check(question_type: str) -> bool:
    """Returns True if this question type should be AI-checked."""
    return question_type in AI_CHECK_TYPES
