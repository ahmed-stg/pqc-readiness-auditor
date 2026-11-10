FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

ENTRYPOINT ["python", "-m", "src.dashboard.fastapi_app", "run", "--port", "8080"]
CMD []
