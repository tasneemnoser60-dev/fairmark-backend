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
ALLOWED_TYPES = {"mcq", "tf", "essay", "short_answer", "matching", "term"}

MATH_KEYWORDS = [
    "calculate",
    "compute",
    "find",
    "determine",
    "solve",
    "derive",
    "prove",
    "show that",
    "evaluate",
    "simplify",
    "integrate",
    "differentiate",
    "convert",
    "transform",
    "express",
    "obtain",
    "plot",
    "sketch",
]

EXAM_PROMPT = """
Extract the exam from the image(s) and return ONLY valid JSON.
No markdown, no explanation, no code fences - raw JSON only.

{
  "title": "string",
  "subject": "string",
  "questions": [
    {
      "id": 1,
      "text": "question text here",
      "points": 1,
      "options": ["A. ...", "B. ...", "C. ...", "D. ..."],
      "correct_answer": "",
      "model_answer": ""
    }
  ]
}

RULES:
- Extract full question text exactly as written
- options: include ONLY if answer choices (A/B/C/D) are visible, otherwise []
- points: extract if shown, otherwise 1
- correct_answer: extract if answer key is visible, otherwise ""
- If multiple images are provided, merge all questions in order
- DO NOT return anything except the raw JSON object
"""


def build_classify_prompt(questions: list) -> str:
    q_lines = "\n".join(
        [
            f"{q['id']}. {q['text']} "
            f"[options: {q.get('options', [])}] "
            f"[correct_answer: {q.get('correct_answer', '')}] "
            f"[points: {q.get('points', 1)}]"
            for q in questions
        ]
    )
    return f"""
You are a question type classifier. Classify each question into exactly one of:
mcq, tf, essay, short_answer, matching, term

Questions:
{q_lines}

Return ONLY valid JSON, no markdown:
{{
  "classifications": [
    {{"id": 1, "type": "mcq | tf | essay | short_answer | matching | term"}}
  ]
}}

CLASSIFICATION RULES (apply strictly in this order):
1. options list is not empty -> MUST be "mcq"
2. correct_answer is T, F, True, or False -> MUST be "tf"
3. points >= 5 -> MUST be "essay"
4. question requires ANY calculation, math, numerical working, or formula -> MUST be "essay"
5. question contains numbers with operations, variables, or equations -> MUST be "essay"
6. question contains a data table, matrix, array, or signal values -> MUST be "essay"
7. question uses words like: calculate, compute, find, determine, solve, derive, prove,
   show that, evaluate, simplify, integrate, differentiate, convert, transform,
   express, obtain, plot, sketch -> MUST be "essay"
8. question is a factual statement (not ending in ?) with no options -> "tf"
9. a description is given and student must write the name of a device/term/concept -> "term"
10. requires a brief answer of 1-2 sentences -> "short_answer"
11. anything else requiring a long written response -> "essay"
"""


def extract_exam(image_path: str) -> dict:
    return extract_exam_multi([image_path])


def extract_exam_multi(image_paths: list) -> dict:
    logger.info("Processing %s image(s)...", len(image_paths))
    images = []
    for p in image_paths:
        try:
            images.append(Image.open(p))
        except Exception as e:
            logger.warning("Could not open image %s: %s", p, e)

    if not images:
        logger.error("No valid images could be opened")
        return {"title": "Untitled", "subject": "UNKNOWN", "questions": [], "confidence": 0.0}

    for attempt in range(MAX_RETRIES):
        try:
            logger.info("Attempt %s: extracting questions...", attempt + 1)
            response = model.generate_content([EXAM_PROMPT] + images)
            data = _extract_json(response.text)
            data = _normalize_fields(data)

            if not data.get("questions"):
                logger.warning("Attempt %s: no questions extracted", attempt + 1)
                continue

            logger.info("Extracted %s questions, classifying types...", len(data["questions"]))
            classify_prompt = build_classify_prompt(data["questions"])
            classify_response = model.generate_content([classify_prompt])
            classifications = _extract_json(classify_response.text)

            data = _apply_classifications(data, classifications)

            if _is_consistent_exam(data):
                data["confidence"] = _compute_confidence_exam(data)
                logger.info(
                    "Done. %s questions, confidence=%s",
                    len(data["questions"]),
                    data["confidence"],
                )
                return data

            logger.warning("Attempt %s: inconsistent IDs", attempt + 1)

        except Exception as e:
            logger.warning("Attempt %s failed: %s", attempt + 1, e)
            traceback.print_exc()

    return {"title": "Untitled", "subject": "UNKNOWN", "questions": [], "confidence": 0.0}


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


def _to_int(value, default=1):
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if value is None:
        return default

    match = re.search(r"\d+", str(value))
    if not match:
        return default

    try:
        return int(match.group())
    except ValueError:
        return default


def _normalize_fields(data: dict) -> dict:
    questions = data.get("questions", [])
    normalized = []

    for i, q in enumerate(questions, start=1):
        normalized.append(
            {
                "id": i,
                "text": str(q.get("text", "")).strip(),
                "points": _to_int(q.get("points", 1), default=1),
                "options": q.get("options", []) if isinstance(q.get("options", []), list) else [],
                "correct_answer": str(q.get("correct_answer", "")).strip().lower(),
                "model_answer": q.get("model_answer", ""),
                "type": "unknown",
            }
        )

    data["questions"] = normalized
    return data


def _apply_classifications(data: dict, classifications: dict) -> dict:
    type_map = {
        c.get("id"): c.get("type")
        for c in classifications.get("classifications", [])
        if c.get("type") in ALLOWED_TYPES
    }

    for q in data["questions"]:
        classified_type = type_map.get(q["id"])
        correct = q.get("correct_answer", "").strip().lower()
        options = q.get("options", [])
        points = q.get("points", 1)
        text_lower = q.get("text", "").lower()

        if options and len(options) >= 2:
            q["type"] = "mcq"
        elif correct in ("t", "f", "true", "false"):
            q["type"] = "tf"
        elif points >= 5:
            q["type"] = "essay"
        elif any(k in text_lower for k in MATH_KEYWORDS):
            q["type"] = "essay"
        elif classified_type:
            q["type"] = classified_type
        else:
            q["type"] = "short_answer"

    return data


def _is_consistent_exam(data: dict) -> bool:
    questions = data.get("questions", [])
    if not questions:
        return False
    ids = [q["id"] for q in questions]
    return len(ids) == len(set(ids))


def _compute_confidence_exam(data: dict) -> float:
    questions = data.get("questions", [])
    if not questions:
        return 0.0
    score = sum(
        (1 if q.get("text") else 0) + (1 if q.get("type") in ALLOWED_TYPES else 0)
        for q in questions
    )
    return round(score / (len(questions) * 2), 2)
