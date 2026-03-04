FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic sqlalchemy psycopg2-binary redis pyjwt

COPY services/control-plane/main.py ./main.py
COPY services/control-plane/db.py ./db.py
COPY services/control-plane/models.py ./models.py

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
