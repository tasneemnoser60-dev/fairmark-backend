import json
import logging
import os
import re
import traceback

import google.generativeai as genai
from dotenv import load_dotenv
from PIL import Image

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== Config =====
load_dotenv()
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

MAX_RETRIES = 3


def build_prompt(questions: list) -> str:
    q_text = "\n".join([f"{q['id']}. [{q['type']}] {q['text']}" for q in questions])
    return f"""
You are extracting a student's answers from an answer sheet image.
The answer sheet may be handwritten or printed.

Here are the exam questions for reference:
{q_text}

Return ONLY valid JSON - no markdown, no explanation, no code fences.

{{
  "answers": [
    {{
      "question_id": 1,
      "answer": "student answer here"
    }}
  ]
}}

EXTRACTION RULES:
- One answer entry per question, no exceptions
- MCQ [mcq] -> return only the selected letter: a, b, c, or d (lowercase only)
- True/False [tf] -> return only: true or false (lowercase only)
- Term [term] -> return the exact word or short phrase the student wrote
- Short answer [short_answer] -> return the student's text as written
- Essay [essay] -> return the full text the student wrote, including any calculations or working
- If a question has no answer written -> return "na"
- If the handwriting is completely unreadable -> return "unclear"
- Do NOT evaluate, grade, or judge any answer
- Do NOT add any text outside the JSON
- If multiple pages are provided, find answers across all pages
"""


def extract_answers(image_path: str, questions: list) -> dict:
    return extract_answers_multi([image_path], questions)


def extract_answers_multi(image_paths: list, questions: list) -> dict:
    logger.info("Processing %s answer sheet image(s)...", len(image_paths))
    images = []
    for p in image_paths:
        try:
            images.append(Image.open(p))
        except Exception as e:
            logger.warning("Could not open image %s: %s", p, e)

    if not images:
        logger.error("No valid images could be opened")
        return {"answers": [], "confidence": 0.0}

    for attempt in range(MAX_RETRIES):
        try:
            prompt = build_prompt(questions)
            response = model.generate_content([prompt] + images)
            data = _extract_json(response.text)
            data = _normalize_answers(data, questions)

            if _is_consistent_answers(data, questions):
                data["confidence"] = _compute_confidence_answers(data)
                logger.info(
                    "Extracted %s answers, confidence=%s",
                    len(data["answers"]),
                    data["confidence"],
                )
                return data

            logger.warning(
                "Attempt %s: answer mismatch (%s vs %s expected)",
                attempt + 1,
                len(data.get("answers", [])),
                len(questions),
            )

        except Exception as e:
            logger.warning("Attempt %s failed: %s", attempt + 1, e)
            traceback.print_exc()

    return {"answers": [], "confidence": 0.0}


def _extract_json(text: str) -> dict:
    cleaned = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

    decoder = json.JSONDecoder()
    for i, ch in enumerate(cleaned):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(cleaned[i:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue

    raise ValueError("No valid JSON object found in response")


def _normalize_question_id(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _normalize_answers(data: dict, questions: list) -> dict:
    data.setdefault("answers", [])
    if not isinstance(data["answers"], list):
        data["answers"] = []

    normalized = []
    seen_ids = set()

    for a in data["answers"]:
        qid = _normalize_question_id(a.get("question_id"))
        if qid in seen_ids:
            continue
        seen_ids.add(qid)

        normalized.append(
            {
                "question_id": qid,
                "answer": str(a.get("answer", "na")).strip().lower() or "na",
            }
        )

    existing_ids = {a["question_id"] for a in normalized}
    for q in questions:
        qid = _normalize_question_id(q.get("id"))
        if qid not in existing_ids:
            normalized.append({"question_id": qid, "answer": "na"})

    normalized.sort(key=lambda x: str(x["question_id"]))
    data["answers"] = normalized
    return data


def _is_consistent_answers(data: dict, questions: list) -> bool:
    answers = data.get("answers", [])
    question_ids = {_normalize_question_id(q.get("id")) for q in questions}
    answer_ids = {a.get("question_id") for a in answers}
    return len(answers) == len(question_ids) and answer_ids == question_ids


def _compute_confidence_answers(data: dict) -> float:
    answers = data.get("answers", [])
    if not answers:
        return 0.0
    valid = sum(1 for a in answers if a.get("answer") not in ("na", "unclear"))
    return round(valid / len(answers), 2)
