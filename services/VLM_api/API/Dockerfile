FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=7860

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vlm_api.py .
COPY exam_processor2.py .
COPY answer_processor2.py .
COPY linker2.py .

EXPOSE 7860

CMD ["python", "vlm_api.py"]
