FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=7860
ENV EMBEDDING_DEVICE=cpu

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY grading_api.py .
COPY grading ./grading

RUN mkdir -p teacher_materials model_answers saved_index

EXPOSE 7860

CMD ["python", "grading_api.py"]
