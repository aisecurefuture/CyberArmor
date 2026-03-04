FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic sqlalchemy psycopg2-binary

COPY services/policy/main.py ./main.py
COPY services/policy/db.py ./db.py
COPY services/policy/models.py ./models.py
COPY services/policy/policy_engine.py ./policy_engine.py

EXPOSE 8001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
