FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY aisafe.example.yaml /app/aisafe.example.yaml

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir "fastapi>=0.100" "uvicorn[standard]>=0.20" "httpx>=0.24" "pydantic>=2" "pyyaml>=6.0" "click>=8.0" "anyio>=4.0"

ENV PYTHONPATH=/app/src
ENV AISAFE_UPSTREAM_BASE_URL=https://api.openai.com

EXPOSE 8000

CMD ["python", "-m", "aisafeguard.cli.main", "proxy", "--host", "0.0.0.0", "--port", "8000", "--config", "/app/aisafe.example.yaml"]
