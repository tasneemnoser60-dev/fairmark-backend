# AI Detection Service

This Flask service is deployed separately from the Node backend.

## Railway setup

Do not commit model weights to Git. Upload the model folder to the server or a Railway Volume, then point the service to it with `AI_MODEL_PATH`.

Required model folder example:

```text
/data/fairmark_ai_detector_best/
  config.json
  model.safetensors
  tokenizer.json
  tokenizer_config.json
  vocab.json
  merges.txt
  special_tokens_map.json
```

Railway variables:

```env
AI_MODEL_PATH=/data/fairmark_ai_detector_best
AI_THRESHOLD=70
PORT=5000
```

Start command:

```bash
python app.py
```

After deploy, test:

```bash
GET /health
POST /predict
Body: { "text": "Your answer text here" }
```

If `/health` returns `503`, the model folder is missing or incomplete. The response will include the exact error.
