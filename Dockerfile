FROM python:3.13-slim

WORKDIR /app

# Install CA certificates for outbound HTTPS requests
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY gateway.py .
COPY token_store.py .

EXPOSE 3001

CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "3001"]
