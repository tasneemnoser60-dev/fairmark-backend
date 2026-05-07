import json
import logging
import os
import uuid
from pathlib import Path

from flask import Flask, jsonify, request

from answer_processor2 import extract_answers_multi
from exam_processor2 import extract_exam_multi
from linker2 import link_questions_to_answers

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

TEMP = Path("temp")
TEMP.mkdir(exist_ok=True)


def save_upload(file) -> Path:
    ext = Path(file.filename).suffix or ".jpg"
    path = TEMP / f"{uuid.uuid4().hex}{ext}"
    file.save(path)
    return path


def collect_images(flask_request) -> list:
    files = flask_request.files.getlist("images")
    if not files or (len(files) == 1 and files[0].filename == ""):
        single = flask_request.files.get("image")
        files = [single] if single else []
    if not files:
        return []
    return [save_upload(f) for f in files]


def cleanup(paths):
    if not isinstance(paths, list):
        paths = [paths]
    for path in paths:
        try:
            p = Path(path)
            if p.exists():
                p.unlink()
        except Exception as e:
            logger.warning("Cleanup failed for %s: %s", path, e)


@app.route("/health")
def health():
    return jsonify({"status": "VLM ok"})


@app.route("/process-exam", methods=["POST"])
def process_exam():
    paths = []
    try:
        paths = collect_images(request)
        logger.info("Files received: %s", [p.name for p in paths])

        if not paths:
            return jsonify({"error": "no image(s) provided. Use 'image' or 'images' field"}), 400

        logger.info("/process-exam received %s image(s)", len(paths))
        result = extract_exam_multi([str(p) for p in paths])
        return jsonify(result)

    except Exception as e:
        logger.error("/process-exam error: %s", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cleanup(paths)


@app.route("/process-answers", methods=["POST"])
def process_answers():
    questions_raw = request.form.get("questions")
    if not questions_raw:
        return jsonify({"error": "missing 'questions' field (paste the questions JSON array)"}), 400

    try:
        questions = json.loads(questions_raw)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"'questions' is not valid JSON: {e}"}), 400

    if not isinstance(questions, list) or not questions:
        return jsonify({"error": "'questions' must be a non-empty JSON array"}), 400

    paths = []
    try:
        paths = collect_images(request)
        if not paths:
            return jsonify({"error": "no image(s) provided. Use 'image' or 'images' field"}), 400

        logger.info(
            "/process-answers received %s image(s) for %s questions",
            len(paths),
            len(questions),
        )
        result = extract_answers_multi([str(p) for p in paths], questions)
        return jsonify(result)

    except Exception as e:
        logger.error("/process-answers error: %s", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cleanup(paths)


@app.route("/link", methods=["POST"])
def link():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "request body must be JSON"}), 400

    exam = data.get("exam")
    answers = data.get("answers")

    if not exam:
        return jsonify({"error": "missing 'exam' field"}), 400
    if not answers:
        return jsonify({"error": "missing 'answers' field"}), 400
    if not exam.get("questions"):
        return jsonify({"error": "'exam.questions' is empty"}), 400
    if not answers.get("answers"):
        return jsonify({"error": "'answers.answers' is empty"}), 400

    try:
        result = link_questions_to_answers(exam, answers)
        return jsonify(result)
    except Exception as e:
        logger.error("/link error: %s", e)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5001")), debug=False)
