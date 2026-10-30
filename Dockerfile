# Glass Ballot: stdlib-only Python, so the image is just Python plus the source.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY glassballot ./glassballot
COPY scripts ./scripts

RUN useradd --create-home --uid 1000 app && mkdir -p /data && chown app /data
USER app

EXPOSE 8080
# TLS is terminated by the platform's proxy; --proxy trusts its X-Forwarded-* headers.
# Bulletin boards live on the /data volume so they survive restarts and redeploys.
CMD ["python", "scripts/serve.py", "--host", "0.0.0.0", "--port", "8080", "--proxy", "--db", "/data/glassballot.db"]
