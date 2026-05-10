from flask import Flask, request, jsonify
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

app = Flask(__name__)

# Load model once at startup
MODEL_PATH = "fairmark_ai_detector"

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.to(device)
model.eval()


def predict_ai_percentage(text):
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True
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

    human, ai = predict_ai_percentage(text)

    decision = "rejected" if ai >= 75 else "accepted"

    return jsonify({
        "human_percentage": human,
        "ai_percentage": ai,
        "decision": decision
    })


if __name__ == "__main__":
    app.run(debug=True)
