FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx pydantic msal boto3 cryptography

COPY libs/aishields-core /app/libs/aishields-core
ENV PYTHONPATH="/app/libs/aishields-core:${PYTHONPATH}"

COPY services/identity/ /app/

EXPOSE 8004
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8004"]
