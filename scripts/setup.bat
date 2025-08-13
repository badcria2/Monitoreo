@echo off
chcp 65001 > nul
echo ================================================
echo  Netskope-Wazuh Integration Setup
echo ================================================

REM Verificar Docker
docker --version > nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker no está instalado o no está ejecutándose
    pause
    exit /b 1
)
echo Docker verificado correctamente.

REM Crear estructura de directorios
echo.
echo Creando estructura de directorios...
if not exist "logs" mkdir logs
if not exist "wazuh-indexer-certs" mkdir wazuh-indexer-certs
if not exist "wazuh-dashboard-certs" mkdir wazuh-dashboard-certs
if not exist "wazuh-config\rules" mkdir wazuh-config\rules
if not exist "wazuh-config\decoders" mkdir wazuh-config\decoders
if not exist "integrations" mkdir integrations

REM Generar certificados SSL
echo Generando certificados SSL...
echo Generando certificados autofirmados...

REM Certificado CA raíz
openssl genrsa -out wazuh-indexer-certs\root-ca-key.pem 2048
openssl req -new -x509 -sha256 -key wazuh-indexer-certs\root-ca-key.pem -out wazuh-indexer-certs\root-ca.pem -days 3650 -subj "/C=ES/ST=Madrid/L=Madrid/O=Wazuh/OU=IT/CN=root-ca"

REM Certificado para wazuh-indexer
openssl genrsa -out wazuh-indexer-certs\wazuh-indexer-key.pem 2048
openssl req -new -key wazuh-indexer-certs\wazuh-indexer-key.pem -out wazuh-indexer-certs\wazuh-indexer.csr -subj "/C=ES/ST=Madrid/L=Madrid/O=Wazuh/OU=IT/CN=wazuh-indexer"
openssl x509 -req -in wazuh-indexer-certs\wazuh-indexer.csr -CA wazuh-indexer-certs\root-ca.pem -CAkey wazuh-indexer-certs\root-ca-key.pem -CAcreateserial -out wazuh-indexer-certs\wazuh-indexer.pem -days 3650 -sha256

REM Certificado para wazuh-dashboard
openssl genrsa -out wazuh-dashboard-certs\wazuh-dashboard-key.pem 2048
openssl req -new -key wazuh-dashboard-certs\wazuh-dashboard-key.pem -out wazuh-dashboard-certs\wazuh-dashboard.csr -subj "/C=ES/ST=Madrid/L=Madrid/O=Wazuh/OU=IT/CN=wazuh-dashboard"
openssl x509 -req -in wazuh-dashboard-certs\wazuh-dashboard.csr -CA wazuh-indexer-certs\root-ca.pem -CAkey wazuh-indexer-certs\root-ca-key.pem -CAcreateserial -out wazuh-dashboard-certs\wazuh-dashboard.pem -days 3650 -sha256

REM Copiar certificados CA a ambas carpetas
copy wazuh-indexer-certs\root-ca.pem wazuh-dashboard-certs\root-ca.pem
copy wazuh-indexer-certs\root-ca-key.pem wazuh-dashboard-certs\root-ca-key.pem

REM Crear archivos de configuración adicionales para indexer
echo Creando archivos de configuración SSL...

REM Admin certificate (para administración)
openssl genrsa -out wazuh-indexer-certs\admin-key.pem 2048
openssl req -new -key wazuh-indexer-certs\admin-key.pem -out wazuh-indexer-certs\admin.csr -subj "/C=ES/ST=Madrid/L=Madrid/O=Wazuh/OU=IT/CN=admin"
openssl x509 -req -in wazuh-indexer-certs\admin.csr -CA wazuh-indexer-certs\root-ca.pem -CAkey wazuh-indexer-certs\root-ca-key.pem -CAcreateserial -out wazuh-indexer-certs\admin.pem -days 3650 -sha256

REM Node certificate (alias para indexer)
copy wazuh-indexer-certs\wazuh-indexer.pem wazuh-indexer-certs\indexer.pem
copy wazuh-indexer-certs\wazuh-indexer-key.pem wazuh-indexer-certs\indexer-key.pem

echo Configurando permisos de certificados...
REM En Windows, asegurar que los archivos sean legibles
attrib -r wazuh-indexer-certs\*.pem
attrib -r wazuh-dashboard-certs\*.pem

REM Crear configuración del dashboard
echo Creando configuración del dashboard...
echo server.host: "0.0.0.0" > wazuh-config\wazuh_dashboard.yml
echo server.port: 5601 >> wazuh-config\wazuh_dashboard.yml
echo opensearch.hosts: ["https://wazuh.indexer:9200"] >> wazuh-config\wazuh_dashboard.yml
echo opensearch.ssl.verificationMode: certificate >> wazuh-config\wazuh_dashboard.yml
echo opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"] >> wazuh-config\wazuh_dashboard.yml
echo opensearch.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem" >> wazuh-config\wazuh_dashboard.yml
echo opensearch.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem" >> wazuh-config\wazuh_dashboard.yml
echo opensearch.username: "admin" >> wazuh-config\wazuh_dashboard.yml
echo opensearch.password: "SecretPassword" >> wazuh-config\wazuh_dashboard.yml
echo wazuh_monitoring.enabled: true >> wazuh-config\wazuh_dashboard.yml
echo wazuh_monitoring.frequency: 900 >> wazuh-config\wazuh_dashboard.yml
echo wazuh_monitoring.shards: 2 >> wazuh-config\wazuh_dashboard.yml
echo wazuh_monitoring.replicas: 0 >> wazuh-config\wazuh_dashboard.yml

REM Crear configuración de integración
echo Creando archivo de configuración de integración en integrations\config.json...
(
echo {
echo   "netskope": {
echo     "api_token": "YOUR_NETSKOPE_TOKEN",
echo     "tenant": "YOUR_TENANT.goskope.com",
echo     "api_version": "v2",
echo     "endpoints": {
echo       "events": "/api/v2/events/dataexport/events/page",
echo       "applications": "/api/v2/events/dataexport/events/application", 
echo       "audit": "/api/v2/events/dataexport/events/audit",
echo       "clients": "/api/v1/clients"
echo     },
echo     "polling_interval": 300,
echo     "batch_size": 1000
echo   },
echo   "wazuh": {
echo     "manager_host": "wazuh.manager",
echo     "manager_port": 1514,
echo     "indexer_host": "wazuh.indexer",
echo     "indexer_port": 9200
echo   },
echo   "monitoring": {
echo     "endpoint_check_interval": 600,
echo     "alert_thresholds": {
echo       "offline_minutes": 30,
echo       "disconnected_minutes": 60
echo     }
echo   }
echo }
) > integrations\config.json

echo Archivo config.json creado en: integrations\config.json

echo Configurando permisos...

echo.
echo ================================================
echo  Setup completado exitosamente!
echo ================================================

echo.
echo Próximos pasos:
echo 1. Configurar variables en el archivo .env
echo 2. Ejecutar: start.bat para iniciar los servicios
echo 3. Acceder a Wazuh Dashboard en: http://localhost:5601

echo.
echo Credenciales por defecto:
echo - Usuario: admin
echo - Contraseña: SecretPassword

echo.
echo IMPORTANTE: Los certificados SSL han sido generados correctamente
echo Ubicación de certificados:
echo - Indexer: wazuh-indexer-certs\
echo - Dashboard: wazuh-dashboard-certs\

pause