# VLM API Service

## Endpoints
- `GET /health`
- `POST /process-exam` (form-data: `image` or `images`)
- `POST /process-answers` (form-data: `image` or `images` + `questions` JSON array)
- `POST /link` (JSON: `{ "exam": {...}, "answers": {...} }`)

## Local run
```bash
pip install -r requirements.txt
copy .env.example .env
# set GOOGLE_API_KEY in .env
python vlm_api.py
```

## Railway run
- Root Directory: `services/VLM_api/API`
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn -w 2 -k gthread -b 0.0.0.0:$PORT vlm_api:app`
- Variables: `GOOGLE_API_KEY`
