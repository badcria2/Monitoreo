@echo off
:: Iniciar Netskope-Wazuh Integration

echo ================================================
echo  Iniciando Netskope-Wazuh Integration
echo ================================================
echo.

:: Verificar que existe el archivo .env
if not exist ".env" (
    echo ERROR: Archivo .env no encontrado
    echo Por favor ejecute setup.bat primero y configure las variables
    pause
    exit /b 1
)

:: Verificar configuración mínima
findstr /R "NETSKOPE_TENANT.*=" .env >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: NETSKOPE_TENANT no configurado en .env
    pause
    exit /b 1
)

findstr /R "NETSKOPE_API_TOKEN.*=" .env >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: NETSKOPE_TOKEN no configurado en .env
    pause
    exit /b 1
)

echo Configuración verificada.
echo.

:: Detener contenedores existentes si están ejecutándose
echo Deteniendo contenedores existentes...
docker compose down >nul 2>&1

:: Construir imágenes
echo Construyendo imágenes Docker...
docker compose build --no-cache

if %errorlevel% neq 0 (
    echo ERROR: Fallo en la construcción de imágenes
    pause
    exit /b 1
)

:: Iniciar servicios
echo.
echo Iniciando servicios...
echo.

:: Iniciar en orden: indexer, manager, dashboard, integration
echo [1/4] Iniciando Wazuh Indexer...
docker compose up -d wazuh-indexer

:: Esperar que indexer esté listo
echo Esperando que Wazuh Indexer esté listo...
timeout /t 30 >nul

echo [2/4] Iniciando Wazuh Manager...
docker compose up -d wazuh-manager

:: Esperar que manager esté listo
echo Esperando que Wazuh Manager esté listo...
timeout /t 30 >nul

echo [3/4] Iniciando Wazuh Dashboard...
docker compose up -d wazuh-dashboard

:: Esperar que dashboard esté listo
echo Esperando que Wazuh Dashboard esté listo...
timeout /t 20 >nul

echo [4/4] Iniciando Netskope Integration...
docker compose up -d netskope-integration

echo.
echo ================================================
echo  Servicios iniciados exitosamente!
echo ================================================
echo.

:: Mostrar estado de los contenedores
echo Estado de los contenedores:
docker compose ps

echo.
echo Endpoints disponibles:
echo - Wazuh Dashboard: http://localhost:5601
echo - Wazuh API:      https://localhost:55000
echo - Wazuh Manager:  localhost:1514 (logs)
echo.
echo Credenciales por defecto:
echo - Usuario: admin
echo - Contraseña: SecretPassword
echo.

:: Verificar logs de integración
echo Verificando logs de integración...
timeout /t 5 >nul
docker logs netskope-integration --tail 10

echo.
echo Para monitorear logs en tiempo real, use:
echo docker compose logs -f netskope-integration
echo.
echo Para detener todos los servicios, use: stop.bat
echo.
pause