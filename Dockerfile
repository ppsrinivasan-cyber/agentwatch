# AgentWatch – zero third-party dependencies, Python stdlib only.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY agentwatch ./agentwatch
COPY mock_webhook ./mock_webhook
COPY config ./config
COPY data ./data
COPY scripts ./scripts
COPY tests ./tests
# Runs as root so the ./output bind mount is writable on Linux hosts; for production, use a
# named volume and add: RUN useradd -u 10001 aw && chown -R aw /app/output  +  USER aw
RUN mkdir -p /app/output
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'),timeout=2)" || exit 1
CMD ["python", "-m", "agentwatch.server"]
