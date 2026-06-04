from flask import Flask, request, jsonify
import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

app = Flask(__name__)

AI_THRESHOLD = float(os.getenv("AI_THRESHOLD", "70"))
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
REQUIRED_MODEL_FILES = ("config.json",)
REQUIRED_WEIGHT_FILES = ("model.safetensors", "pytorch_model.bin")

tokenizer = None
model = None
MODEL_PATH = None
MODEL_ERROR = None


def has_model_weights(path):
    return any(os.path.exists(os.path.join(path, name)) for name in REQUIRED_WEIGHT_FILES)


def validate_model_path(path):
    if not path:
        return "AI_MODEL_PATH is required"
    if not os.path.isdir(path):
        return f"AI_MODEL_PATH does not exist or is not a directory: {path}"

    missing = [name for name in REQUIRED_MODEL_FILES if not os.path.exists(os.path.join(path, name))]
    if missing:
        return f"AI model folder is missing required file(s): {', '.join(missing)}"

    if not has_model_weights(path):
        return "AI model folder is missing model weights: model.safetensors or pytorch_model.bin"

    return None


def resolve_model_path():
    return os.getenv("AI_MODEL_PATH", "fairmark_ai_detector_best")


def load_model():
    global tokenizer, model, MODEL_PATH, MODEL_ERROR
    if model is not None:
        return True

    MODEL_PATH = resolve_model_path()
    MODEL_ERROR = validate_model_path(MODEL_PATH)
    if MODEL_ERROR:
        return False

    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, ignore_mismatched_sizes=True)
        model.to(device)
        model.eval()
        MODEL_ERROR = None
        return True
    except Exception as exc:
        MODEL_ERROR = f"Failed to load AI model from {MODEL_PATH}: {exc}"
        model = None
        tokenizer = None
        return False


@app.route("/health")
def health():
    model_ready = load_model()
    return jsonify({
        "status": "AI Detection API ok",
        "model_path": MODEL_PATH or resolve_model_path(),
        "model_loaded": model_ready,
        "threshold": AI_THRESHOLD,
        "device": str(device),
        "error": MODEL_ERROR
    }), 200 if model_ready else 503


def predict_ai_percentage(text):
    if not load_model():
        raise RuntimeError(MODEL_ERROR or "AI model is not loaded")

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512
    ).to(device)

    with torch.no_grad():
        outputs = model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)

    human_prob = probs[0][0].item() * 100
    ai_prob = probs[0][1].item() * 100

    return human_prob, ai_prob


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not isinstance(text, str) or not text.strip():
        return jsonify({"error": "text is required"}), 400

    try:
        human, ai = predict_ai_percentage(text)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503

    decision = "rejected" if ai >= AI_THRESHOLD else "accepted"

    return jsonify({
        "human_percentage": human,
        "ai_percentage": ai,
        "decision": decision
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
