# CyberSentinel backend — production image for AWS ECS / EC2 / App Runner
# Build from repo root: docker build -t cybersentinel-backend .

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBUG=false \
    HOST=0.0.0.0 \
    PORT=8000

WORKDIR /app

# System libs for cryptography, reportlab, scikit-learn wheels fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY cybersentinel-backend/requirements.txt /app/cybersentinel-backend/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r /app/cybersentinel-backend/requirements.txt

# Application + ML code and trained artifacts (paths relative to cybersentinel-backend/)
COPY cybersentinel-backend/ /app/cybersentinel-backend/
COPY supervised_learning/ /app/supervised_learning/
COPY unsupervised_learning/ /app/unsupervised_learning/

WORKDIR /app/cybersentinel-backend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
