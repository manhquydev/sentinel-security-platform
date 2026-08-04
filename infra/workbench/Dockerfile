FROM python:3.12-alpine
RUN addgroup -S workbench && adduser -S -G workbench -u 10001 workbench
WORKDIR /app
COPY workbench /app/workbench
USER workbench
EXPOSE 4173
CMD ["python3", "-m", "workbench.web.app"]
