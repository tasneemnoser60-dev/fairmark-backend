"""
grader.py
=========
Core grading logic with fair scoring.

Priority (strictly enforced — no unnecessary Gemini calls):
  1. Teacher model answer  → use directly, no RAG, no Gemini
  2. RAG material          → use as reference, Gemini only for borderline scoring
  3. Gemini fallback       → LAST resort only when no model answer and no RAG

MCQ / TF:
  - Teacher answer  → direct comparison, zero Gemini calls
  - RAG available   → one Gemini call to extract correct answer from context
  - No RAG          → one Gemini call as last resort

Short Answer:
  - Similarity against model answer or RAG context
  - Gemini only for borderline range (0.55 – 0.80)
  - Outside range → similarity score only, no Gemini

Essay:
  - Similarity against model answer or RAG context
  - Very high (≥ 0.90) → full marks, no Gemini
  - Very low  (≤ 0.15) → zero marks, no Gemini
  - Borderline         → one Gemini call for nuanced scoring

NOTE on casing:
  VLM answer extraction normalizes MCQ/TF to lowercase but preserves
  casing for essay/short_answer. AI detection therefore receives
  properly cased essay text, making RoBERTa reliable again.
  MCQ/TF grading compares lowercase → lowercase as before.
"""

import os
import re
import json
import time
import logging
from dotenv import load_dotenv

import torch
import google.generativeai as genai
from sentence_transformers import SentenceTransformer, util

load_dotenv()
logger = logging.getLogger(__name__)

# ===== Models =====
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
gemini_model = genai.GenerativeModel("gemini-2.5-flash")

similarity_model = SentenceTransformer(
    "sentence-transformers/all-roberta-large-v1",
    device=os.getenv("EMBEDDING_DEVICE") or ("cuda" if torch.cuda.is_available() else "cpu")
)

# ===== Config =====
GEMINI_DELAY = float(os.getenv("GEMINI_DELAY", "0"))


# =========================================================
# GEMINI
# =========================================================

def _call_gemini(prompt: str) -> str:
    """Rate-limited Gemini call."""
    time.sleep(GEMINI_DELAY)
    response = gemini_model.generate_content(prompt)
    return response.text.strip()


# =========================================================
# RAG
# =========================================================

def _get_context(retriever, query: str) -> str:
    """
    Retrieve RAG context if retriever is available.
    Returns empty string if retriever is None or retrieval fails.
    """
    if retriever is None:
        return ""
    try:
        from grading.rag_indexer import retrieve_context_text
        return retrieve_context_text(retriever, query)
    except Exception as e:
        logger.warning(f"RAG retrieval failed: {e}")
        return ""


# =========================================================
# MODEL ANSWER RESOLUTION
# =========================================================

def resolve_model_answer(
    model_answer: str,
    retriever,
    question_text: str,
    question_type: str
) -> tuple:
    """
    Resolve the best available reference answer.

    Returns (answer, source, rag_context) where:
      - answer      : the reference text to grade against
      - source      : where it came from
      - rag_context : raw RAG context (used for weighted similarity)
                      empty if teacher answer was used (not needed)

    Priority:
      1. Teacher model answer → return immediately, no RAG, no Gemini
      2. RAG context          → return context directly as reference
      3. Gemini knowledge     → last resort only
    """

    # ── Priority 1: teacher model answer ──────────────────────
    if model_answer and model_answer.strip():
        logger.info("Using teacher model answer — skipping RAG and Gemini")
        return model_answer.strip(), "teacher-model-answer", ""

    # ── Priority 2: RAG context ────────────────────────────────
    rag_context = _get_context(retriever, question_text)

    if rag_context.strip():
        logger.info("Using RAG context as reference answer")
        return rag_context.strip(), "rag-material", rag_context

    # ── Priority 3: Gemini fallback ────────────────────────────
    logger.warning(
        f"No model answer or RAG — falling back to Gemini for: "
        f"{question_text[:60]}"
    )

    prompt = f"""
Provide a concise academic model answer for the following question.

Question: {question_text}
Question type: {question_type}

Return ONLY the model answer, no extra text.
"""
    try:
        answer = _call_gemini(prompt)
        return answer, "gemini-knowledge", ""
    except Exception as e:
        logger.warning(f"Gemini model answer extraction failed: {e}")
        return "", "failed", ""


# =========================================================
# SIMILARITY
# =========================================================

def compute_similarity(student_answer: str, reference_answer: str) -> float:
    """Simple cosine similarity between two texts."""
    embeddings = similarity_model.encode(
        [student_answer, reference_answer],
        convert_to_tensor=True
    )
    score = util.pytorch_cos_sim(embeddings[0], embeddings[1]).item()
    return round(max(0.0, min(1.0, score)), 4)


def compute_weighted_similarity(
    student_answer: str,
    model_answer: str,
    rag_context: str
) -> float:
    """
    Weighted similarity — model answer weighted 1.5x, RAG context 1x.
    Falls back to simple similarity if no RAG context.
    """
    if not rag_context.strip():
        return compute_similarity(student_answer, model_answer)

    embeddings = similarity_model.encode(
        [student_answer, model_answer, rag_context],
        convert_to_tensor=True
    )

    sim_model = util.pytorch_cos_sim(embeddings[0], embeddings[1]).item()
    sim_rag   = util.pytorch_cos_sim(embeddings[0], embeddings[2]).item()
    weighted  = (1.5 * sim_model + 1.0 * sim_rag) / 2.5

    return round(max(0.0, min(1.0, weighted)), 4)


def similarity_to_score(similarity: float, max_score: float) -> float:
    """Continuous scoring — no harsh fixed brackets."""
    if similarity >= 0.90:
        ratio = 1.0
    elif similarity >= 0.75:
        ratio = 0.75 + (similarity - 0.75) / (0.90 - 0.75) * 0.25
    elif similarity >= 0.55:
        ratio = 0.50 + (similarity - 0.55) / (0.75 - 0.55) * 0.25
    elif similarity >= 0.35:
        ratio = 0.10 + (similarity - 0.35) / (0.55 - 0.35) * 0.40
    else:
        ratio = 0.0
    return round(ratio * max_score, 2)


# =========================================================
# GEMINI SECOND OPINION (short answer borderline only)
# =========================================================

def _gemini_verify_short_answer(
    student_answer: str,
    model_answer: str,
    question_text: str,
    max_score: float
) -> float:
    """
    Called ONLY for borderline short answers (0.55 – 0.80 similarity).
    Returns a score out of max_score.
    """
    prompt = f"""
You are a fair academic grader. Reward correct understanding even if wording differs.

Question: {question_text}
Expected Answer: {model_answer}
Student Answer: {student_answer}
Maximum score: {max_score}

Return ONLY a number between 0 and {max_score}.
"""
    try:
        result = _call_gemini(prompt)
        score  = float(result.strip())
        return round(max(0.0, min(float(max_score), score)), 2)
    except Exception as e:
        logger.warning(f"Gemini short answer verification failed: {e}")
        return similarity_to_score(0.65, max_score)


# =========================================================
# MCQ GRADING
# =========================================================

def grade_mcq(
    student_answer: str,
    retriever,
    question_text: str,
    options: list,
    correct_answer: str
) -> dict:
    """
    Grade MCQ.
    Priority: teacher answer → RAG → Gemini fallback.
    MCQ answers are always lowercase (normalized by VLM extractor).
    """

    # ── Priority 1: teacher answer ─────────────────────────────
    if correct_answer and correct_answer.strip():
        raw     = correct_answer.strip().lower()
        match   = re.search(r"[abcd]", raw)
        correct = match.group() if match else raw[0]
        source  = "teacher-model-answer"

    else:
        correct = ""
        source  = ""

        # ── Priority 2: RAG ────────────────────────────────────
        if retriever:
            context = _get_context(retriever, question_text)

            if context.strip():
                options_text = "\n".join(options)
                prompt = f"""
Based ONLY on the course material context below,
determine the correct MCQ answer.

Question: {question_text}
Options:
{options_text}

Context:
{context}

Return ONLY one letter: a, b, c, or d
"""
                try:
                    raw   = _call_gemini(prompt).lower()
                    match = re.search(r"[abcd]", raw)
                    if match:
                        correct = match.group()
                        source  = "rag-material"
                except Exception as e:
                    logger.warning(f"MCQ RAG extraction failed: {e}")

        # ── Priority 3: Gemini fallback ────────────────────────
        if not correct:
            logger.warning(f"MCQ Gemini fallback: {question_text[:60]}")
            options_text = "\n".join(options)
            prompt = f"""
What is the correct answer for this MCQ?

Question: {question_text}
Options:
{options_text}

Return ONLY one letter: a, b, c, or d
"""
            try:
                raw     = _call_gemini(prompt).lower()
                match   = re.search(r"[abcd]", raw)
                correct = match.group() if match else "a"
                source  = "gemini-fallback"
            except Exception as e:
                logger.warning(f"MCQ Gemini fallback failed: {e}")
                correct = "a"
                source  = "failed"

    is_correct = student_answer.strip().lower() == correct

    return {
        "correct_answer": correct,
        "is_correct":     is_correct,
        "grading_source": source,
        "justification": (
            f"Correct answer is '{correct}' ({source}). "
            f"Student answered '{student_answer}' — "
            f"{'correct' if is_correct else 'incorrect'}."
        )
    }


# =========================================================
# TRUE / FALSE GRADING
# =========================================================

def grade_tf(
    student_answer: str,
    retriever,
    question_text: str,
    correct_answer: str
) -> dict:
    """
    Grade True/False.
    Priority: teacher answer → RAG → Gemini fallback.
    TF answers are always lowercase (normalized by VLM extractor).
    """

    # ── Priority 1: teacher answer ─────────────────────────────
    if (
        correct_answer and
        correct_answer.strip().lower() in ("true", "false", "t", "f")
    ):
        correct = (
            "true"
            if correct_answer.strip().lower() in ("true", "t")
            else "false"
        )
        source = "teacher-model-answer"

    else:
        correct = ""
        source  = ""

        # ── Priority 2: RAG ────────────────────────────────────
        if retriever:
            context = _get_context(retriever, question_text)

            if context.strip():
                prompt = f"""
Based ONLY on the course material context below,
determine whether the statement is true or false.

Statement: {question_text}

Context:
{context}

Return ONLY: true or false
"""
                try:
                    raw = _call_gemini(prompt).lower()
                    if "true" in raw:
                        correct = "true"
                        source  = "rag-material"
                    elif "false" in raw:
                        correct = "false"
                        source  = "rag-material"
                except Exception as e:
                    logger.warning(f"TF RAG extraction failed: {e}")

        # ── Priority 3: Gemini fallback ────────────────────────
        if not correct:
            logger.warning(f"TF Gemini fallback: {question_text[:60]}")
            prompt = f"""
Is this statement true or false?

Statement: {question_text}

Return ONLY: true or false
"""
            try:
                raw     = _call_gemini(prompt).lower()
                correct = "true" if "true" in raw else "false"
                source  = "gemini-fallback"
            except Exception as e:
                logger.warning(f"TF Gemini fallback failed: {e}")
                correct = "false"
                source  = "failed"

    student_norm = student_answer.strip().lower()

    if student_norm == "t":
        student_norm = "true"
    elif student_norm == "f":
        student_norm = "false"
    
    is_correct = student_norm == correct

    return {
        "correct_answer": correct,
        "is_correct":     is_correct,
        "grading_source": source,
        "justification": (
            f"Statement is '{correct}' ({source}). "
            f"Student answered '{student_answer}' — "
            f"{'correct' if is_correct else 'incorrect'}."
        )
    }


# =========================================================
# SHORT ANSWER GRADING
# =========================================================

def grade_short_answer(
    student_answer: str,
    retriever,
    question_text: str,
    model_answer: str,
    max_score: float
) -> dict:
    """
    Grade short answer using similarity scoring.
    Gemini called ONLY for borderline range (0.55 – 0.80).

    NOTE: student_answer preserves original casing from VLM extractor
    (casing fix applied in answer_processor.py for essay/short_answer types).
    """

    final_answer, source, rag_context = resolve_model_answer(
        model_answer, retriever, question_text, "short_answer"
    )

    similarity = compute_weighted_similarity(
        student_answer, final_answer, rag_context
    )

    # ── Borderline → Gemini second opinion ────────────────────
    if 0.55 <= similarity <= 0.80:
        roberta_score = similarity_to_score(similarity, max_score)
        gemini_score  = _gemini_verify_short_answer(
            student_answer, final_answer, question_text, max_score
        )
        score  = round((roberta_score + gemini_score) / 2, 2)
        method = "similarity+gemini"

    # ── Clear match or clear mismatch → similarity only ───────
    else:
        score  = similarity_to_score(similarity, max_score)
        method = "similarity"

    return {
        "score":          score,
        "max_score":      max_score,
        "similarity":     similarity,
        "grading_method": method,
        "grading_source": source,
        "justification": (
            f"Similarity: {similarity:.2f}. "
            f"Method: {method}. "
            f"Source: {source}. "
            f"Score: {score}/{max_score}."
        )
    }


# =========================================================
# ESSAY GRADING
# =========================================================

def grade_essay(
    student_answer: str,
    retriever,
    question_text: str,
    model_answer: str,
    max_score: float
) -> dict:
    """
    Grade essay using similarity + Gemini for borderline only.

    Fast paths (no Gemini):
      similarity >= 0.90 → full marks
      similarity <= 0.15 → zero marks

    Gemini path (one call):
      0.15 < similarity < 0.90 → nuanced scoring

    NOTE: student_answer preserves original casing from VLM extractor
    (casing fix applied in answer_processor.py for essay/short_answer types).
    RoBERTa in ai_detector.py therefore receives properly cased text.
    """

    final_answer, source, rag_context = resolve_model_answer(
        model_answer, retriever, question_text, "essay"
    )

    similarity = compute_weighted_similarity(
        student_answer, final_answer, rag_context
    )

    # ── Fast path: very high similarity ───────────────────────
    if similarity >= 0.90:
        logger.info(f"Essay high similarity ({similarity:.2f}) — full marks, no Gemini")
        return {
            "score":          round(max_score, 2),
            "max_score":      max_score,
            "similarity":     similarity,
            "grading_method": "high-similarity",
            "grading_source": source,
            "justification":  (
                f"Very high semantic similarity ({similarity:.2f}) — "
                f"full marks awarded."
            )
        }

    # ── Fast path: very low similarity ────────────────────────
    if similarity <= 0.15:
        logger.info(f"Essay low similarity ({similarity:.2f}) — zero marks, no Gemini")
        return {
            "score":          0.0,
            "max_score":      max_score,
            "similarity":     similarity,
            "grading_method": "low-similarity",
            "grading_source": source,
            "justification":  (
                f"Answer fundamentally differs from expected solution "
                f"({similarity:.2f})."
            )
        }

    # ── Borderline → Gemini nuanced scoring ───────────────────
    logger.info(
        f"Essay borderline similarity ({similarity:.2f}) — "
        f"calling Gemini for nuanced scoring"
    )

    context_section = (
        f"\nAdditional Course Context:\n{rag_context}\n"
        if rag_context.strip()
        else ""
    )

    prompt = f"""
You are a fair university grader.

Question: {question_text}

Expected Answer ({source}):
{final_answer}
{context_section}
Student Answer:
{student_answer}

Maximum Score: {max_score}
Semantic Similarity: {similarity:.2f}

Grading Rules:
- Reward correct understanding even if wording differs
- Give partial credit where deserved
- Partial credit for correct method with small arithmetic errors
- Do NOT penalize for different wording, notation, or step order
- Be fair and conservative — do not over-penalize

Return ONLY valid JSON, no markdown:
{{
  "score": <number between 0 and {max_score}>,
  "justification": "<one or two sentence explanation>"
}}
"""

    text = _call_gemini(prompt)
    text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

    try:
        result        = json.loads(text)
        score         = float(result.get("score", 0))
        score         = max(0.0, min(float(max_score), score))
        justification = result.get("justification", "")
    except Exception:
        logger.warning(f"Essay grading parse failed — using similarity fallback: {text}")
        score         = similarity_to_score(similarity, max_score)
        justification = f"Fallback similarity grading used ({similarity:.2f})."

    return {
        "score":          round(score, 2),
        "max_score":      max_score,
        "similarity":     similarity,
        "grading_method": "gemini-borderline",
        "grading_source": source,
        "justification":  justification
    }
