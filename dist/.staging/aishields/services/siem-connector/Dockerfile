FROM python:3.11-slim
LABEL maintainer="AIShields <security@aishields.ai>"
RUN groupadd -r aishields && useradd -r -g aishields -m aishields
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx pydantic
COPY services/siem-connector/ /app/
USER aishields
EXPOSE 8005
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005"]
