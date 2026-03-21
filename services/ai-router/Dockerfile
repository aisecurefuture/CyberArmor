FROM python:3.11-slim
WORKDIR /app
COPY services/ai-router/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/ai-router/ /app/
COPY scripts/security/run_uvicorn_tls.py /app/run_uvicorn_tls.py
EXPOSE 8009
CMD ["python", "run_uvicorn_tls.py", "main:app", "8009"]
