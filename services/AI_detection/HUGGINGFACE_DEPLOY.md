# Hugging Face Space Deploy

Use this folder as a Docker Space.

## Required Files

- `app.py`
- `requirements.txt`
- `Dockerfile`
- `.dockerignore`
- `fairmark_ai_detector_best/`

The model folder must include:

- `config.json`
- `merges.txt`
- `model.safetensors`
- `special_tokens_map.json`
- `tokenizer_config.json`
- `tokenizer.json`
- `vocab.json`

## Space Settings

- SDK: Docker
- Port: `7860`

## Backend Env

After the Space is running, set Railway backend:

```env
AI_DETECTION_URL=https://YOUR-SPACE.hf.space/predict
```

Then redeploy the backend.
