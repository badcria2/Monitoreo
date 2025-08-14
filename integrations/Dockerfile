FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY netskope_endpoint_monitor.py .

CMD ["python", "netskope_endpoint_monitor.py"]