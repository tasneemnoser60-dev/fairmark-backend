"""
grading_router.py
=================
Routes each question to the correct grader.
Passes question_text to AI detector for enriched detection.
Handles retriever=None gracefully (Gemini-only mode).

Fixes applied:
  1. Removed duplicate check_answer call
  2. Removed dead comment
  3. batch_extract_answers uses _call_gemini
  4. Removed direct genai import (no longer needed)
  5. correct_answer falls back to model_answer if empty
  6. T/F answers in essay/short_answer questions handled correctly
  7. batch_extract skips questions that already have model_answer
"""

import re
import json
import logging

from grading.grader import (
    grade_mcq,
    grade_tf,
    grade_short_answer,
    grade_essay,
    _get_context,
    _call_gemini,
)
from grading.ai_detector import check_answer, should_check

logger = logging.getLogger(__name__)


# ===== BATCH EXTRACT MCQ/TF ANSWERS =====

def batch_extract_answers(linked_questions: list, retriever) -> dict:
    """
    Extract correct answers for ALL MCQ/TF in ONE Gemini call.
    Skips questions that already have correct_answer or model_answer.
    Works with or without RAG context.
    """
    target_qs = [
        q for q in linked_questions
        if q["type"] in ("mcq", "tf")
        and not q.get("correct_answer", "").strip()
        and not q.get("model_answer", "").strip()
        and q.get("attempted", True)
        and q.get("student_answer", "na") not in ("na", "unclear", "")
    ]

    if not target_qs:
        logger.info("All MCQ/TF already have correct answers, skipping batch extraction")
        return {}

    logger.info(f"Batch extracting {len(target_qs)} MCQ/TF answers...")

    combined_query = " ".join([q["question"] for q in target_qs])
    context        = _get_context(retriever, combined_query)

    q_lines = "\n".join([
        f"{q['question_id']}. [{q['type']}] {q['question']}"
        + (f"\n   Options: {q.get('options', [])}" if q["type"] == "mcq" else "")
        for q in target_qs
    ])

    if context:
        prompt = f"""
Based on the course material context below, determine the correct answer for each question.

Questions:
{q_lines}

Course material context:
{context}

Return ONLY valid JSON, no markdown:
{{
  "answers": [
    {{"question_id": 1, "correct_answer": "b"}},
    {{"question_id": 16, "correct_answer": "false"}}
  ]
}}

Rules:
- MCQ: return only the letter a, b, c, or d (lowercase)
- True/False: return only true or false (lowercase)
- Base answers strictly on the course material provided
"""
    else:
        logger.warning("No RAG context — using Gemini knowledge for MCQ/TF answers")
        prompt = f"""
You are an academic grading assistant. Determine the correct answer for each question.

Questions:
{q_lines}

Return ONLY valid JSON, no markdown:
{{
  "answers": [
    {{"question_id": 1, "correct_answer": "b"}},
    {{"question_id": 16, "correct_answer": "false"}}
  ]
}}

Rules:
- MCQ: return only the letter a, b, c, or d (lowercase)
- True/False: return only true or false (lowercase)
"""

    try:
        text   = _call_gemini(prompt)
        text   = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
        data   = json.loads(text)
        result = {a["question_id"]: a["correct_answer"] for a in data.get("answers", [])}
        logger.info(f"Batch extraction complete: {len(result)} answers")
        return result
    except Exception as e:
        logger.error(f"Batch extraction failed: {e}")
        return {}


# ===== GRADE SINGLE QUESTION =====

def grade_question(linked_question: dict, retriever, use_api: bool = False) -> dict:
    """
    Grade a single linked question.
    Passes question_text to AI detector for enriched stylometric analysis.
    """
    qid            = linked_question["question_id"]
    qtype          = linked_question["type"]
    question_text  = linked_question["question"]
    student_answer = linked_question["student_answer"]
    model_answer   = linked_question.get("model_answer", "")
    max_score      = float(linked_question.get("max_score", 1))
    attempted      = linked_question.get("attempted", True)
    needs_review   = linked_question.get("needs_manual_review", False)

    # FIX: fall back to model_answer if correct_answer is empty
    # Teacher model answer upload sets model_answer, not correct_answer
    correct_answer = (
        linked_question.get("correct_answer", "").strip()
        or linked_question.get("model_answer", "").strip()
    )

    result = {
        "question_id":         qid,
        "type":                qtype,
        "question":            question_text,
        "student_answer":      student_answer,
        "max_score":           max_score,
        "score":               0.0,
        "justification":       "",
        "needs_manual_review": needs_review,
        "ai_detection":        None,
        "grading_mode":        "rag" if retriever else "gemini-only"
    }

    # ── Not attempted ──────────────────────────────────────────
    if not attempted or student_answer in ("na", ""):
        result["justification"] = "Question not attempted."
        return result

    # ── Unclear handwriting ────────────────────────────────────
    if needs_review or student_answer == "unclear":
        result["justification"]       = "Answer marked as unclear. Needs manual review."
        result["needs_manual_review"] = True
        return result

    # ── Smart AI Detection ─────────────────────────────────────
    normalized_answer = re.sub(r"[^a-z]", "", student_answer.lower())
    SKIP_AI_ANSWERS   = {"true", "false", "t", "f", "a", "b", "c", "d"}

    if normalized_answer in SKIP_AI_ANSWERS:
        logger.info(f"Q{qid}: Skipping AI detection (answer: '{student_answer}')")

    elif should_check(qtype):
        logger.info(f"Q{qid} [{qtype}]: Running AI detection...")
        ai_result = check_answer(
            text=student_answer,
            use_api=use_api,
            question_text=question_text
        )

        result["ai_detection"] = {
            "ai_percentage":    ai_result["ai_percentage"],
            "human_percentage": ai_result["human_percentage"],
            "decision":         ai_result["decision"],
            "flagged_by":       ai_result.get("flagged_by", []),
            "weighted_score":   ai_result.get("weighted_score", 0.0),
            "roberta_result":   ai_result.get("roberta_result"),
            "gemini_result":    ai_result.get("gemini_result")
        }

        if ai_result["flagged"]:
            flagged_by = ai_result.get("flagged_by", [])

            result["score"] = 0.0

            result["justification"] = (
                f"Answer flagged as AI-generated "
                f"({ai_result['ai_percentage']:.1f}% weighted confidence, "
                f"flagged by: {', '.join(flagged_by)}). Score set to 0."
            )

            result["needs_manual_review"] = True

            logger.warning(
                f"Q{qid} FLAGGED as AI by {flagged_by}. Score = 0."
            )

            return result

        logger.info(
            f"Q{qid} passed AI check "
            f"(weighted: {ai_result.get('weighted_score', 0)*100:.1f}%). Grading..."
        )

    # ── Detect T/F answers inside essay/short_answer questions ─
    # Handles cases where question type is essay but answer is true/false
    if qtype in ("essay", "short_answer"):
        normalized = student_answer.strip().lower()
        if normalized in ("true", "false", "t", "f"):
            grading = grade_tf(
                student_answer, retriever, question_text, correct_answer
            )
            result["score"]          = max_score if grading["is_correct"] else 0.0
            result["correct_answer"] = grading["correct_answer"]
            result["justification"]  = grading["justification"]
            logger.info(
                f"Q{qid} [{qtype}]: T/F answer detected in essay — graded as T/F"
            )
            return result

    # ── Grade ──────────────────────────────────────────────────
    try:
        if qtype == "mcq":
            grading = grade_mcq(
                student_answer, retriever, question_text,
                linked_question.get("options", []), correct_answer
            )
            result["score"]          = max_score if grading["is_correct"] else 0.0
            result["correct_answer"] = grading["correct_answer"]
            result["justification"]  = grading["justification"]

        elif qtype == "tf":
            grading = grade_tf(
                student_answer, retriever, question_text, correct_answer
            )
            result["score"]          = max_score if grading["is_correct"] else 0.0
            result["correct_answer"] = grading["correct_answer"]
            result["justification"]  = grading["justification"]

        elif qtype in ("short_answer", "term"):
            grading = grade_short_answer(
                student_answer, retriever, question_text, model_answer, max_score
            )
            result["score"]          = grading["score"]
            result["similarity"]     = grading.get("similarity")
            result["grading_method"] = grading.get("grading_method")
            result["justification"]  = grading["justification"]

        elif qtype == "essay":
            grading = grade_essay(
                student_answer, retriever, question_text, model_answer, max_score
            )
            result["score"]         = grading["score"]
            result["justification"] = grading["justification"]

        elif qtype == "matching":
            grading = grade_short_answer(
                student_answer, retriever, question_text, model_answer, max_score
            )
            result["score"]         = grading["score"]
            result["similarity"]    = grading.get("similarity")
            result["justification"] = grading["justification"]

        else:
            logger.warning(f"Unknown type '{qtype}' for Q{qid}, using essay grading")
            grading = grade_essay(
                student_answer, retriever, question_text, model_answer, max_score
            )
            result["score"]         = grading["score"]
            result["justification"] = grading["justification"]

    except Exception as e:
        logger.error(f"Error grading Q{qid}: {e}")
        result["score"]               = 0.0
        result["justification"]       = f"Grading error: {str(e)}"
        result["needs_manual_review"] = True

    logger.info(
        f"Q{qid} [{qtype}]: {result['score']}/{max_score} — "
        f"{result['justification'][:60]}"
    )
    return result


# ===== GRADE ALL =====

def grade_all(linked_questions: list, retriever, use_api: bool = False) -> dict:
    """
    Grade all linked questions.
    retriever=None → Gemini-only mode (no crash).
    """
    mode = "RAG + Gemini" if retriever else "Gemini only (no material uploaded)"
    logger.info(f"Grading mode: {mode}")

    # Batch extract MCQ/TF correct answers (only if not already provided)
    batch_answers = batch_extract_answers(linked_questions, retriever)

    # Inject extracted answers
    for q in linked_questions:
        qid = q["question_id"]
        if qid in batch_answers and not q.get("correct_answer", "").strip():
            q["correct_answer"] = batch_answers[qid]
            logger.debug(f"Q{qid}: injected correct_answer='{batch_answers[qid]}'")

    # Grade each question
    results     = []
    total_score = 0.0
    total_max   = 0.0
    ai_flagged  = []

    for q in linked_questions:
        result = grade_question(q, retriever, use_api=use_api)
        results.append(result)
        total_score += result["score"]
        total_max   += result["max_score"]

        if result.get("ai_detection") and result["ai_detection"]["decision"] == "rejected":
            ai_flagged.append(result["question_id"])

    percentage = round((total_score / total_max * 100), 2) if total_max > 0 else 0.0

    summary = {
        "total_score":          round(total_score, 2),
        "total_max":            round(total_max, 2),
        "percentage":           percentage,
        "grading_mode":         mode,
        "ai_flagged_questions": ai_flagged,
        "needs_manual_review":  [
            r["question_id"] for r in results
            if r.get("needs_manual_review")
            and r["question_id"] not in ai_flagged
        ],
        "grade_results": results
    }

    logger.info(
        f"Done: {total_score}/{total_max} ({percentage}%) | "
        f"AI flagged: {len(ai_flagged)} | "
        f"Manual review: {len(summary['needs_manual_review'])}"
    )
    return summary