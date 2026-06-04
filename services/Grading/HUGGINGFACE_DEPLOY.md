# Hugging Face Space Deploy

Use this folder as a Docker Space for the FairMark Grading API.

## Required Files

- `grading_api.py`
- `requirements.txt`
- `Dockerfile`
- `.dockerignore`
- `grading/`

Do not upload local runtime folders:

- `.venv/`
- `.venv311/`
- `teacher_materials/`
- `model_answers/`
- `saved_index/`
- `__pycache__/`

## Space Settings

- SDK: Docker
- Port: `7860`

## Space Variables

Add these secrets/variables in the Hugging Face Space settings:

```env
GOOGLE_API_KEY=your_google_api_key
AI_DETECTION_URL=https://tasnem11-fairmark-ai-detection.hf.space/predict
USE_DETECTOR_API=false
EMBEDDING_DEVICE=cpu
```

## Health Check

After the Space is running:

```text
https://YOUR-GRADING-SPACE.hf.space/health
```

Expected:

```json
{ "status": "Grading API ok" }
```

## Backend Env

After the Space is running, set Railway backend:

```env
GRADING_API_URL=https://YOUR-GRADING-SPACE.hf.space
```
