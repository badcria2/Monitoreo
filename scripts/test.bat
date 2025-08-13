@echo off
:: Script de prueba para Netskope-Wazuh Integration

echo ================================================
echo  Netskope-Wazuh Integration - Pruebas
echo ================================================
echo.

:: Verificar estado de contenedores
echo [1/6] Estado de contenedores:
echo =====================================
docker compose ps
echo.

:: Verificar conectividad de Wazuh Manager
echo [2/6] Verificando Wazuh Manager (puerto 55000):
echo =============================================
curl -k -u wazuh-wui:MyS3cr37P450r.*- https://localhost:55000/ 2>nul
if %errorlevel% neq 0 (
    echo ERROR: No se puede conectar a Wazuh Manager API
) else (
    echo OK: Wazuh Manager API responde
)
echo.

:: Verificar Wazuh Dashboard
echo [3/6] Verificando Wazuh Dashboard (puerto 5601):
echo ===========================================
curl -s http://localhost:5601/app/wazuh 2>nul | findstr "Wazuh" >nul
if %errorlevel% neq 0 (
    echo ERROR: Wazuh Dashboard no responde correctamente
) else (
    echo OK: Wazuh Dashboard accesible
)
echo.

:: Verificar logs de integración
echo [4/6] Logs recientes de integración Netskope:
echo =========================================
docker logs netskope-integration --tail 20
echo.

:: Verificar configuración de Netskope
echo [5/6] Verificando configuración de Netskope:
echo ========================================
if exist ".env" (
    findstr "NETSKOPE_TENANT" .env | findstr /v "^#"
    findstr "NETSKOPE_TOKEN" .env | findstr /v "^#" | findstr /v "your-api"
    if %errorlevel% neq 0 (
        echo ADVERTENCIA: Token de Netskope parece no estar configurado
    )
) else (
    echo ERROR: Archivo .env no encontrado
)
echo.

:: Verificar archivos de logs
echo [6/6] Verificando archivos de logs:
echo ==============================
if exist "logs\" (
    dir logs\ /b
    echo.
    if exist "logs\netskope_client_status.log" (
        echo Últimas entradas en netskope_client_status.log:
        powershell "Get-Content logs\netskope_client_status.log -Tail 5"
    )
    if exist "logs\netskope_events.log" (
        echo.
        echo Últimas entradas en netskope_events.log:
        powershell "Get-Content logs\netskope_events.log -Tail 5"
    )
) else (
    echo Directorio de logs no encontrado
)
echo.

:: Verificar conectividad con Netskope (si está configurado)
echo [Adicional] Prueba de conectividad con Netskope:
echo ============================================
for /f "tokens=2 delims==" %%a in ('findstr "NETSKOPE_TENANT" .env 2^>nul') do set TENANT=%%a
if defined TENANT (
    set TENANT=%TENANT: =%
    echo Probando conectividad con %TENANT%...
    ping %TENANT% -n 1 >nul 2>&1
    if %errorlevel% equ 0 (
        echo OK: %TENANT% es alcanzable
    ) else (
        echo ADVERTENCIA: No se puede hacer ping a %TENANT%
    )
) else (
    echo NETSKOPE_TENANT no configurado
)

echo.
echo ================================================
echo  Pruebas completadas
echo ================================================
echo.
echo Comandos útiles para diagnóstico:
echo - Ver logs en tiempo real: docker compose logs -f
echo - Acceder al contenedor: docker exec -it netskope-integration /bin/bash
echo - Reiniciar integración: docker compose restart netskope-integration
echo - Verificar reglas Wazuh: docker exec wazuh-manager cat /var/ossec/etc/rules/local_rules/netskope_rules.xml
echo.
pause