FROM python:3.11-slim

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar archivos de requirements
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar scripts de integración
COPY netskope_integration.py .
COPY netskope_endpoint_monitor.py .
COPY config.json .

# Crear directorio para logs
RUN mkdir -p /var/log/netskope-wazuh

# Crear usuario no privilegiado
RUN useradd -m -u 1000 netskope && \
    chown -R netskope:netskope /app /var/log/netskope-wazuh

USER netskope

# Comando por defecto
CMD ["python", "netskope_integration.py"]