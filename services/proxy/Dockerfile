FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir mitmproxy fastapi uvicorn httpx cryptography pydantic

COPY libs/aishields-core /app/libs/aishields-core
ENV PYTHONPATH="/app/libs/aishields-core:${PYTHONPATH}"

COPY services/proxy/ /app/

EXPOSE 8080 8443 8081
CMD ["mitmdump", "-s", "transparent_proxy.py", "--listen-port", "8080"]
