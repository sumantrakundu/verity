FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr exiftool libgl1 libglib2.0-0 && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/verity
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN mkdir -p /tmp/verity-work /tmp/verity-data
ENV DATABASE_PATH=/tmp/verity-data/verity.sqlite3 UPLOAD_TEMP_DIR=/tmp/verity-work TESSERACT_CMD=/usr/bin/tesseract EXIFTOOL_CMD=/usr/bin/exiftool
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
