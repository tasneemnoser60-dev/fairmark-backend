import logging

logger = logging.getLogger(__name__)


def _normalize_question_id(value):
    """Normalize IDs so int/string mismatches do not break linking."""
    try:
        return str(int(value))
    except (TypeError, ValueError):
        return str(value).strip()


def link_questions_to_answers(exam: dict, answers: dict) -> list:
    """
    Link exam questions with student answers into a unified list.

    Args:
        exam: output from extract_exam() containing 'questions'
        answers: output from extract_answers() containing 'answers'

    Returns:
        List of linked dicts, one per question
    """
    answer_map = {
        _normalize_question_id(a.get("question_id")): a.get("answer", "na")
        for a in answers.get("answers", [])
    }

    linked = []
    for q in exam.get("questions", []):
        qid = q.get("id")
        normalized_qid = _normalize_question_id(qid)
        ans = answer_map.get(normalized_qid, "na")
        q_type = q.get("type", "essay")

        linked.append(
            {
                "question_id": qid,
                "type": q_type,
                "question": q.get("text", ""),
                "options": q.get("options", []),
                "student_answer": ans,
                "correct_answer": q.get("correct_answer", ""),
                "model_answer": q.get("model_answer", ""),
                "max_score": q.get("points", 1),
                "attempted": ans not in ("na", "unclear"),
                "needs_manual_review": ans == "unclear",
            }
        )

    total = len(linked)
    attempted = sum(1 for x in linked if x["attempted"])
    skipped = sum(1 for x in linked if not x["attempted"])
    unclear = sum(1 for x in linked if x["needs_manual_review"])

    logger.info(
        "Linked %s questions: %s attempted, %s skipped, %s unclear",
        total,
        attempted,
        skipped,
        unclear,
    )

    return linked
