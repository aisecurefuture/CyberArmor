FROM python:3.11-slim
WORKDIR /app
COPY services/audit/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/audit/ /app/
COPY scripts/security/run_uvicorn_tls.py /app/run_uvicorn_tls.py
EXPOSE 8011
CMD ["python", "run_uvicorn_tls.py", "main:app", "8011"]
