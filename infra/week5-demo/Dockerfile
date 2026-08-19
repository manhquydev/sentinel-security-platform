# Teaching facade for Week-5 IPI/HITL/PII. Not the Charter executor.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

RUN useradd --create-home --uid 10001 sentinel
WORKDIR /app

COPY agent/ /app/agent/
COPY tests/fixtures/ /app/tests/fixtures/
COPY scripts/sentinel-week5-demo.py /app/scripts/sentinel-week5-demo.py

USER sentinel
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    SENTINEL_WEEK5_DEMO_CONTAINER=1

EXPOSE 18055
CMD ["python3", "/app/scripts/sentinel-week5-demo.py", "--bind", "0.0.0.0", "--port", "18055"]
