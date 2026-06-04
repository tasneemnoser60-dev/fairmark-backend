# Hugging Face Space Deploy

Use this folder as a Docker Space for the FairMark VLM API.

## Required Files

- `vlm_api.py`
- `exam_processor2.py`
- `answer_processor2.py`
- `linker2.py`
- `requirements.txt`
- `Dockerfile`
- `.dockerignore`

## Space Settings

- SDK: Docker
- Port: `7860`

## Space Variables

Add this secret/variable in the Hugging Face Space settings:

```env
GOOGLE_API_KEY=your_google_api_key
```

## Health Check

After the Space is running:

```text
https://YOUR-VLM-SPACE.hf.space/health
```

Expected:

```json
{ "status": "VLM ok" }
```

## Backend Env

After the Space is running, set Railway backend:

```env
VLM_API_URL=https://YOUR-VLM-SPACE.hf.space
```
