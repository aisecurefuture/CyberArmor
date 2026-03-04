FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx pydantic cryptography

COPY libs/aishields-core /app/libs/aishields-core
ENV PYTHONPATH="/app/libs/aishields-core:${PYTHONPATH}"

COPY agents/proxy-agent/main.py /app/main.py

EXPOSE 8010
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
