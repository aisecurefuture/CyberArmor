FROM python:3.11-slim AS base

LABEL maintainer="CyberArmor.ai <security@aishields.ai>"
LABEL description="CyberArmor.ai Endpoint Agent (containerized mode)"

# Security: run as non-root
RUN groupadd -r aishields && useradd -r -g aishields -m aishields

# System deps for cryptography, watchdog, psutil
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/aishields

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY . .

# Config and data volumes
RUN mkdir -p /etc/cyberarmor /var/log/aishields /var/lib/aishields/quarantine \
    && chown -R aishields:aishields /etc/cyberarmor /var/log/aishields /var/lib/aishields

VOLUME ["/etc/cyberarmor", "/var/log/aishields", "/var/lib/aishields"]

# Environment
ENV CYBERARMOR_CONFIG=/etc/cyberarmor/agent.json
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

USER aishields

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8020/health').raise_for_status()" || exit 1

EXPOSE 8020

ENTRYPOINT ["python", "agent.py"]
CMD ["--config", "/etc/cyberarmor/agent.json"]
