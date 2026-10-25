# ==============================================================================
# ChidFlow: Autonomous AI Agent Invariant Runtime & Clearinghouse Gateway
# ==============================================================================
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY chidflow ./chidflow
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir build && \
    python -m build --wheel

# Production Stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Create non-root user for principle of least privilege
RUN groupadd -g 10001 chidflow && \
    useradd -u 10001 -g chidflow -s /bin/bash -m chidflow

COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER chidflow:chidflow

EXPOSE 8080 8443

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/v1/clearing/status')" || exit 1

ENTRYPOINT ["chidflow"]
CMD ["serve-clearing", "--port", "8443"]
