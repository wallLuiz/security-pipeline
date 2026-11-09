FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY enrich.py .
COPY osv_client.py .

CMD ["python", "enrich.py"]
