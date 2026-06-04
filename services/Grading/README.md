# Grading Service

Flask service for FairMark grading.

Local default port: `5003`.

## Endpoints

- `GET /health`
- `POST /upload-material` multipart: `files` + `course_id`
- `POST /upload-model-answer` multipart: `file` + `questions`
- `POST /grade` JSON: `{ "course_id": "...", "linked_questions": [...] }`

## Local

```bash
pip install -r requirements.txt
python grading_api.py
```

Then set the backend env:

```env
GRADING_API_URL=http://127.0.0.1:5003
```

## Railway

- Root Directory: `services/Grading`
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn -w 1 -k gthread -b 0.0.0.0:$PORT grading_api:app`
- Variables:
  - `GOOGLE_API_KEY`
  - `AI_DETECTION_URL` optional, if `USE_DETECTOR_API=true`
  - `USE_DETECTOR_API=false`
  - `EMBEDDING_DEVICE=cpu` recommended on CPU hosts

Large model weights (`*.safetensors`) are intentionally ignored by git. Add them through your deployment storage/volume if direct AI detection is required.
