FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic

COPY libs/aishields-core /app/libs/aishields-core
ENV PYTHONPATH="/app/libs/aishields-core:${PYTHONPATH}"

COPY services/detection/main.py ./main.py

EXPOSE 8002
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
