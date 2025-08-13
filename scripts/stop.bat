@echo off
:: Detener Netskope-Wazuh Integration

echo ================================================
echo  Deteniendo Netskope-Wazuh Integration
echo ================================================
echo.

:: Mostrar estado actual
echo Estado actual de los contenedores:
docker compose ps

echo.
echo Deteniendo servicios...

:: Detener servicios en orden inverso
docker compose down

if %errorlevel% neq 0 (
    echo.
    echo Forzando detención de contenedores...
    docker stop wazuh-manager wazuh-indexer wazuh-dashboard netskope-integration >nul 2>&1
    docker rm wazuh-manager wazuh-indexer wazuh-dashboard netskope-integration >nul 2>&1
)

echo.
echo ================================================
echo  Servicios detenidos exitosamente
echo ================================================
echo.

:: Verificar que no queden contenedores ejecutándose
echo Verificando contenedores restantes...
docker compose ps

echo.
echo Para eliminar completamente los volúmenes de datos, use:
echo docker compose down -v --remove-orphans
echo.
echo ADVERTENCIA: Esto eliminará todos los datos de Wazuh
echo.
pause