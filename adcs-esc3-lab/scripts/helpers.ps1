# ==============================================================================
# ADCS ESC3 Lab - Helper Functions
# ==============================================================================
# Common utility functions for provisioning scripts
# ==============================================================================

# ==============================================================================
# Logging Helpers
# ==============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colorMap = @{
        "INFO" = "White"
        "SUCCESS" = "Green"
        "WARN" = "Yellow"
        "ERROR" = "Red"
    }
    
    $color = $colorMap[$Level]
    if (-not $color) { $color = "White" }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# ==============================================================================
# Service Helpers
# ==============================================================================

function Wait-ForService {
    param(
        [string]$ServiceName,
        [int]$TimeoutSeconds = 120
    )
    
    Write-Log "Waiting for service: $ServiceName..." "INFO"
    $elapsed = 0
    $interval = 5
    
    while ($elapsed -lt $TimeoutSeconds) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Write-Log "Service $ServiceName is running" "SUCCESS"
            return $true
        }
        
        Start-Sleep -Seconds $interval
        $elapsed += $interval
        Write-Host "  Waiting... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor Gray
    }
    
    Write-Log "Timeout waiting for service: $ServiceName" "ERROR"
    return $false
}

function Test-ServiceRunning {
    param([string]$ServiceName)
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return ($service -and $service.Status -eq 'Running')
}

# ==============================================================================
# Network Helpers
# ==============================================================================

function Test-DomainReachability {
    param(
        [string]$DomainName,
        [string]$DCAddress
    )
    
    Write-Log "Testing domain reachability: $DomainName" "INFO"
    
    # Test DNS resolution
    try {
        $dnsResult = Resolve-DnsName -Name $DomainName -Server $DCAddress -ErrorAction Stop
        Write-Log "DNS resolution successful" "SUCCESS"
    }
    catch {
        Write-Log "DNS resolution failed: $_" "WARN"
        return $false
    }
    
    # Test connectivity
    try {
        $pingResult = Test-Connection -ComputerName $DCAddress -Count 2 -Quiet
        if ($pingResult) {
            Write-Log "DC is reachable" "SUCCESS"
            return $true
        }
    }
    catch {
        Write-Log "Connectivity test failed" "ERROR"
    }
    
    return $false
}

# ==============================================================================
# AD Helpers
# ==============================================================================

function Wait-ForADReady {
    param([int]$TimeoutSeconds = 180)
    
    Write-Log "Waiting for Active Directory to be ready..." "INFO"
    $elapsed = 0
    $interval = 10
    
    while ($elapsed -lt $TimeoutSeconds) {
        try {
            # Try to query AD
            $domain = Get-ADDomain -ErrorAction Stop
            Write-Log "Active Directory is ready" "SUCCESS"
            return $true
        }
        catch {
            Start-Sleep -Seconds $interval
            $elapsed += $interval
            Write-Host "  Waiting for AD... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor Gray
        }
    }
    
    Write-Log "Timeout waiting for Active Directory" "ERROR"
    return $false
}

# ==============================================================================
# WinRM Helpers
# ==============================================================================

function Configure-WinRM {
    Write-Log "Configuring WinRM..." "INFO"
    
    try {
        # Add firewall rule
        $existingRule = Get-NetFirewallRule -Name "AllowWinRMHTTP" -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            New-NetFirewallRule -Name "AllowWinRMHTTP" `
                -DisplayName "Allow WinRM over HTTP" `
                -Enabled True `
                -Protocol TCP `
                -LocalPort 5985 `
                -Action Allow `
                -ErrorAction Stop | Out-Null
            Write-Log "Firewall rule created for WinRM" "SUCCESS"
        }
        
        # Configure WinRM
        winrm quickconfig -quiet -force
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force
        Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
        Restart-Service WinRM -Force
        
        Write-Log "WinRM configured successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "WinRM configuration failed: $_" "ERROR"
        return $false
    }
}

# ==============================================================================
# State Marker Helpers
# ==============================================================================

function Test-StateMarker {
    param([string]$MarkerName)
    
    $markerPath = "C:\Scripts\state\$MarkerName.done"
    return (Test-Path $markerPath)
}

function Set-StateMarker {
    param([string]$MarkerName)
    
    $stateDir = "C:\Scripts\state"
    if (-not (Test-Path $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }
    
    $markerPath = "$stateDir\$MarkerName.done"
    Set-Content -Path $markerPath -Value (Get-Date).ToString()
    Write-Log "State marker set: $MarkerName" "INFO"
}

function Remove-StateMarker {
    param([string]$MarkerName)
    
    $markerPath = "C:\Scripts\state\$MarkerName.done"
    if (Test-Path $markerPath) {
        Remove-Item $markerPath -Force
        Write-Log "State marker removed: $MarkerName" "INFO"
    }
}
