# Netskope-Wazuh Integration Monitor
# PowerShell script para monitorear la integración

param(
    [string]$Action = "status",
    [int]$RefreshInterval = 30
)

# Función para mostrar el encabezado
function Show-Header {
    Clear-Host
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Netskope-Wazuh Integration Monitor" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Función para verificar el estado de los contenedores
function Get-ContainerStatus {
    Write-Host "Estado de Contenedores:" -ForegroundColor Yellow
    Write-Host "======================" -ForegroundColor Yellow
    
    try {
        $containers = docker compose ps --format json | ConvertFrom-Json
        
        foreach ($container in $containers) {
            $name = $container.Name
            $status = $container.State
            $health = if ($container.Health) { $container.Health } else { "N/A" }
            
            $color = switch ($status) {
                "running" { "Green" }
                "exited" { "Red" }
                "restarting" { "Yellow" }
                default { "White" }
            }
            
            Write-Host "  $name : $status ($health)" -ForegroundColor $color
        }
    }
    catch {
        Write-Host "  Error obteniendo estado de contenedores: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# Función para verificar logs recientes
function Get-RecentLogs {
    param([int]$Lines = 10)
    
    Write-Host "Logs Recientes de Integración:" -ForegroundColor Yellow
    Write-Host "==============================" -ForegroundColor Yellow
    
    try {
        $logs = docker logs netskope-integration --tail $Lines 2>&1
        foreach ($line in $logs) {
            if ($line -match "ERROR|CRITICAL") {
                Write-Host "  $line" -ForegroundColor Red
            }
            elseif ($line -match "WARNING|WARN") {
                Write-Host "  $line" -ForegroundColor Yellow
            }
            elseif ($line -match "INFO|SUCCESS") {
                Write-Host "  $line" -ForegroundColor Green
            }
            else {
                Write-Host "  $line" -ForegroundColor White
            }
        }
    }
    catch {
        Write-Host "  Error obteniendo logs: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# Función para verificar métricas de recursos
function Get-ResourceMetrics {
    Write-Host "Uso de Recursos:" -ForegroundColor Yellow
    Write-Host "===============" -ForegroundColor Yellow
    
    try {
        $stats = docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
        $stats | ForEach-Object {
            if ($_ -match "netskope|wazuh") {
                Write-Host "  $_" -ForegroundColor Cyan
            }
        }
    }
    catch {
        Write-Host "  Error obteniendo métricas: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# Función para verificar conectividad de red
function Test-NetworkConnectivity {
    Write-Host "Conectividad de Red:" -ForegroundColor Yellow
    Write-Host "===================" -ForegroundColor Yellow
    
    # Verificar puertos locales
    $ports = @(
        @{Port=5601; Service="Wazuh Dashboard"},
        @{Port=55000; Service="Wazuh API"},
        @{Port=1514; Service="Wazuh Manager"}
    )
    
    foreach ($portInfo in $ports) {
        try {
            $connection = Test-NetConnection -ComputerName localhost -Port $portInfo.Port -InformationLevel Quiet
            $status = if ($connection) { "✓ Abierto" } else { "✗ Cerrado" }
            $color = if ($connection) { "Green" } else { "Red" }
            Write-Host "  Puerto $($portInfo.Port) ($($portInfo.Service)): $status" -ForegroundColor $color
        }
        catch {
            Write-Host "  Puerto $($portInfo.Port) ($($portInfo.Service)): Error" -ForegroundColor Red
        }
    }
    
    # Verificar conectividad con Netskope
    if (Test-Path ".env") {
        $tenant = Get-Content ".env" | Where-Object { $_ -match "NETSKOPE_TENANT=" } | ForEach-Object { $_.Split("=")[1] }
        if ($tenant) {
            $tenant = $tenant.Trim()
            try {
                $ping = Test-Connection -ComputerName $tenant -Count 1 -Quiet
                $status = if ($ping) { "✓ Accesible" } else { "✗ No accesible" }
                $color = if ($ping) { "Green" } else { "Red" }
                Write-Host "  Netskope ($tenant): $status" -ForegroundColor $color
            }
            catch {
                Write-Host "  Netskope ($tenant): Error" -ForegroundColor Red
            }
        }
    }
    Write-Host ""
}

# Función para verificar archivos de logs
function Get-LogFiles {
    Write-Host "Archivos de Logs:" -ForegroundColor Yellow
    Write-Host "=================" -ForegroundColor Yellow
    
    if (Test-Path "logs") {
        $logFiles = Get-ChildItem "logs" -Filter "*.log"
        foreach ($file in $logFiles) {
            $size = [math]::Round($file.Length / 1KB, 2)
            $lastWrite = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "  $($file.Name) - $size KB - Modificado: $lastWrite" -ForegroundColor Cyan
            
            # Mostrar últimas líneas si el archivo fue modificado recientemente
            if ($file.LastWriteTime -gt (Get-Date).AddMinutes(-5)) {
                Write-Host "    Actividad reciente detectada:" -ForegroundColor Yellow
                $recentLines = Get-Content $file.FullName -Tail 3
                foreach ($line in $recentLines) {
                    Write-Host "    $line" -ForegroundColor Gray
                }
            }
        }
    }
    else {
        Write-Host "  Directorio de logs no encontrado" -ForegroundColor Red
    }
    Write-Host ""
}

# Función para generar reporte de salud
function Get-HealthReport {
    Write-Host "Reporte de Salud del Sistema:" -ForegroundColor Yellow
    Write-Host "=============================" -ForegroundColor Yellow
    
    $health = @{
        ContainersRunning = 0
        ContainersTotal = 0
        NetworkPorts = 0
        LogActivity = $false
        NetskopeConnectivity = $false
    }
    
    # Verificar contenedores
    try {
        $containers = docker compose ps --format json | ConvertFrom-Json
        $health.ContainersTotal = $containers.Count
        $health.ContainersRunning = ($containers | Where-Object { $_.State -eq "running" }).Count
    }
    catch { }
    
    # Verificar puertos
    $ports = @(5601, 55000, 1514)
    foreach ($port in $ports) {
        if (Test-NetConnection -ComputerName localhost -Port $port -InformationLevel Quiet) {
            $health.NetworkPorts++
        }
    }
    
    # Verificar actividad de logs
    if (Test-Path "logs") {
        $recentLogs = Get-ChildItem "logs" -Filter "*.log" | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) }
        $health.LogActivity = $recentLogs.Count -gt 0
    }
    
    # Verificar conectividad Netskope
    if (Test-Path ".env") {
        $tenant = Get-Content ".env" | Where-Object { $_ -match "NETSKOPE_TENANT=" } | ForEach-Object { $_.Split("=")[1] }
        if ($tenant) {
            $tenant = $tenant.Trim()
            try {
                $health.NetskopeConnectivity = Test-Connection -ComputerName $tenant -Count 1 -Quiet
            }
            catch { }
        }
    }
    
    # Mostrar resumen
    $overallHealth = if (
        $health.ContainersRunning -eq $health.ContainersTotal -and
        $health.NetworkPorts -eq 3 -and
        $health.LogActivity -and
        $health.NetskopeConnectivity
    ) { "✓ SALUDABLE" } else { "⚠ REQUIERE ATENCIÓN" }
    
    $healthColor = if ($overallHealth -match "✓") { "Green" } else { "Yellow" }
    
    Write-Host "  Estado General: $overallHealth" -ForegroundColor $healthColor
    Write-Host "  Contenedores: $($health.ContainersRunning)/$($health.ContainersTotal) ejecutándose" -ForegroundColor Cyan
    Write-Host "  Puertos de red: $($health.NetworkPorts)/3 abiertos" -ForegroundColor Cyan
    Write-Host "  Actividad de logs: $(if ($health.LogActivity) { '✓ Activa' } else { '✗ Inactiva' })" -ForegroundColor Cyan
    Write-Host "  Conectividad Netskope: $(if ($health.NetskopeConnectivity) { '✓ OK' } else { '✗ Fallo' })" -ForegroundColor Cyan
    Write-Host ""
}

# Función principal de monitoreo
function Start-Monitor {
    while ($true) {
        Show-Header
        Get-ContainerStatus
        Get-HealthReport
        Test-NetworkConnectivity
        Get-RecentLogs -Lines 5
        Get-ResourceMetrics
        Get-LogFiles
        
        Write-Host "Comandos disponibles:" -ForegroundColor Magenta
        Write-Host "  [R] Actualizar    [L] Ver logs completos    [S] Ver estadísticas" -ForegroundColor Gray
        Write-Host "  [T] Probar conexión    [Q] Salir" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Actualizando en $RefreshInterval segundos... (Presiona 'q' para salir)" -ForegroundColor Gray
        
        # Esperar con posibilidad de interrupción
        $timeout = $RefreshInterval
        while ($timeout -gt 0) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                switch ($key.Key) {
                    'Q' { return }
                    'R' { break }
                    'L' { 
                        Clear-Host
                        docker logs netskope-integration --tail 50
                        Write-Host "Presiona cualquier tecla para continuar..."
                        [Console]::ReadKey() | Out-Null
                        break
                    }
                    'S' {
                        Clear-Host
                        docker stats --no-stream
                        Write-Host "Presiona cualquier tecla para continuar..."
                        [Console]::ReadKey() | Out-Null
                        break
                    }
                    'T' {
                        Clear-Host
                        Write-Host "Probando conectividad..." -ForegroundColor Yellow
                        Test-NetworkConnectivity
                        Write-Host "Presiona cualquier tecla para continuar..."
                        [Console]::ReadKey() | Out-Null
                        break
                    }
                }
                break
            }
            Start-Sleep 1
            $timeout--
        }
    }
}

# Ejecutar según la acción solicitada
switch ($Action.ToLower()) {
    "status" {
        Show-Header
        Get-ContainerStatus
        Get-HealthReport
    }
    "logs" {
        Get-RecentLogs -Lines 20
    }
    "monitor" {
        Start-Monitor
    }
    "health" {
        Show-Header
        Get-HealthReport
        Test-NetworkConnectivity
    }
    "resources" {
        Get-ResourceMetrics
    }
    default {
        Write-Host "Uso: monitor.ps1 [-Action <status|logs|monitor|health|resources>] [-RefreshInterval <seconds>]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Acciones disponibles:" -ForegroundColor Cyan
        Write-Host "  status     - Mostrar estado actual" -ForegroundColor Gray
        Write-Host "  logs       - Mostrar logs recientes" -ForegroundColor Gray
        Write-Host "  monitor    - Monitoreo en tiempo real (interactivo)" -ForegroundColor Gray
        Write-Host "  health     - Reporte de salud del sistema" -ForegroundColor Gray
        Write-Host "  resources  - Uso de recursos" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Ejemplo: .\monitor.ps1 -Action monitor -RefreshInterval 10" -ForegroundColor Green
    }
}