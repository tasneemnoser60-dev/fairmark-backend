"""
grading_api.py
==============
Flask API for the grading module. Runs on port 5003 by default.

Handles 3 scenarios automatically:
  1. course_id + model answer  → RAG + provided answers (most accurate)
  2. course_id only            → RAG + auto-extracted answers
  3. No course_id              → Gemini only (still works, less accurate)
"""

from flask import Flask, request, jsonify
import os
import uuid
import json
import re
import logging
from pathlib import Path

import google.generativeai as genai
from dotenv import load_dotenv

from grading.rag_indexer import build_index, load_index
from grading.grading_router import grade_all

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
gemini_model = genai.GenerativeModel("gemini-2.5-flash")

app = Flask(__name__)

UPLOAD_DIR = Path("teacher_materials")
UPLOAD_DIR.mkdir(exist_ok=True)

MODEL_ANSWERS_DIR = Path("model_answers")
MODEL_ANSWERS_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".pptx"}

# False = direct mode, True = call the AI detection API.
USE_DETECTOR_API = os.getenv("USE_DETECTOR_API", "false").lower() == "true"


def save_file(file, folder: Path) -> Path:
    ext = Path(file.filename).suffix.lower()
    path = folder / f"{uuid.uuid4().hex}{ext}"
    file.save(path)
    return path


def cleanup(paths: list):
    for p in paths:
        try:
            if Path(p).exists():
                os.remove(p)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")


def read_file_text(path: str) -> str:
    from grading.rag_indexer import _read_pdf, _read_docx, _read_pptx
    ext = Path(path).suffix.lower()
    if ext == ".pdf":
        return _read_pdf(path)
    elif ext == ".docx":
        return _read_docx(path)
    elif ext == ".pptx":
        return _read_pptx(path)
    return ""


# ===== ROUTES =====

@app.route("/health")
def health():
    return jsonify({
        "status": "Grading API ok",
        "ai_detection_mode": "direct" if not USE_DETECTOR_API else "api"
    })


@app.route("/upload-material", methods=["POST"])
def upload_material():
    """
    Teacher uploads course material to build RAG index.
    Only needed once per course.

    Postman form-data:
        files:     File  (PDF, DOCX, PPTX — multiple rows with key 'files')
        course_id: Text  (e.g. "multimedia_2025")
    """
    course_id = request.form.get("course_id")
    if not course_id:
        return jsonify({"error": "missing 'course_id' field"}), 400

    files = request.files.getlist("files")
    if not files or (len(files) == 1 and files[0].filename == ""):
        return jsonify({"error": "no files provided. Use 'files' field"}), 400

    for f in files:
        ext = Path(f.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error": f"Unsupported: {f.filename}. Allowed: PDF, DOCX, PPTX"}), 400

    paths = []
    try:
        paths = [save_file(f, UPLOAD_DIR) for f in files]
        build_index(material_paths=[str(p) for p in paths], course_id=course_id)
        return jsonify({
            "message": f"Index built for course '{course_id}'",
            "files_indexed": [f.filename for f in files],
            "course_id": course_id
        })
    except Exception as e:
        logger.error(f"/upload-material error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cleanup(paths)


@app.route("/upload-model-answer", methods=["POST"])
def upload_model_answer():
    """
    Teacher optionally uploads model answer document.
    Returns updated questions array with model_answer fields filled.

    Postman form-data:
        file:      File  (PDF or DOCX)
        questions: Text  (JSON array from /process-exam)
    """
    file = request.files.get("file")
    questions_raw = request.form.get("questions")

    if not file:
        return jsonify({"error": "missing 'file' field"}), 400
    if not questions_raw:
        return jsonify({"error": "missing 'questions' field"}), 400

    try:
        questions = json.loads(questions_raw)
    except json.JSONDecodeError:
        return jsonify({"error": "'questions' must be valid JSON array"}), 400

    ext = Path(file.filename).suffix.lower()
    if ext not in {".pdf", ".docx"}:
        return jsonify({"error": "model answer must be PDF or DOCX"}), 400

    path = None
    try:
        path = save_file(file, MODEL_ANSWERS_DIR)
        doc_text = read_file_text(str(path))

        if not doc_text.strip():
            return jsonify({"error": "Could not extract text from model answer document"}), 400

        q_list = "\n".join([
            f"{q['id']}. [{q['type']}] {q['text']}"
            for q in questions
        ])

        prompt = f"""
Extract the correct answer for each question from the model answer document.

Questions:
{q_list}

Model Answer Document:
{doc_text}

Return ONLY valid JSON, no markdown:
{{
  "answers": [
    {{"question_id": 1, "model_answer": "the correct answer"}}
  ]
}}

Rules:
- MCQ: return just the letter (a, b, c, or d)
- True/False: return just "true" or "false"
- Short answer/term: return the expected answer phrase
- Essay/math: return the full model solution
- If not found: return ""
"""
        # WITH THIS:
        from grading.grader import _call_gemini
        text = _call_gemini(prompt)
        text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

        extracted = json.loads(text)
        answer_map = {a["question_id"]: a["model_answer"] for a in extracted.get("answers", [])}
        for q in questions:
            q["model_answer"] = answer_map.get(q["id"], "")

        filled = sum(1 for q in questions if q.get("model_answer", "").strip())
        return jsonify({
            "message": f"Model answers extracted for {filled}/{len(questions)} questions",
            "questions": questions
        })

    except Exception as e:
        logger.error(f"/upload-model-answer error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if path:
            cleanup([path])


@app.route("/grade", methods=["POST"])
def grade():
    """
    Grade a student's linked answers.

    Postman raw JSON:
    {
        "course_id": "multimedia_2025",   ← optional, omit for Gemini-only mode
        "linked_questions": [ ... ]       ← output from /link
    }

    Scenarios handled automatically:
      - course_id provided + material uploaded → RAG + Gemini (most accurate)
      - course_id provided but no material     → warning + Gemini only
      - no course_id                           → Gemini only (less accurate)
    """
    data = request.json
    if not data:
        return jsonify({"error": "request body must be JSON"}), 400

    course_id        = data.get("course_id")
    linked_questions = data.get("linked_questions")

    if not linked_questions:
        return jsonify({"error": "missing 'linked_questions'"}), 400
    if not isinstance(linked_questions, list):
        return jsonify({"error": "'linked_questions' must be a list"}), 400

    # Load retriever if course_id provided — None if not
    retriever = None
    if course_id:
        try:
            retriever = load_index(course_id=course_id)
            logger.info(f"RAG index loaded for course '{course_id}'")
        except FileNotFoundError:
            logger.warning(
                f"No index found for course '{course_id}'. "
                f"Falling back to Gemini-only grading. "
                f"Upload material first for better accuracy."
            )
        except Exception as e:
            logger.warning(f"Could not load index: {e}. Falling back to Gemini-only.")
    else:
        logger.warning("No course_id provided. Grading with Gemini only (less accurate).")

    try:
        results = grade_all(
            linked_questions,
            retriever,          # None = Gemini only, object = RAG mode
            use_api=USE_DETECTOR_API
        )
        return jsonify(results)
    except Exception as e:
        logger.error(f"/grade error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5003")), debug=False)
