# ==============================================================================
# ADCS ESC3 Lab - Client Domain Join Script
# ==============================================================================
# Joins client to domain using DNS auto-discovery (ESC2 lesson learned)
# ==============================================================================

# Import environment variables
$DC_IP = $env:DC_IP
$CLIENT_IP = $env:CLIENT_IP
$DOMAIN_NAME = $env:DOMAIN_NAME
$DOMAIN_NETBIOS = $env:DOMAIN_NETBIOS

# Configuration
$DOMAIN_ADMIN_USER = "$DOMAIN_NETBIOS\Administrator"
$DOMAIN_ADMIN_PASSWORD = "P@ssw0rd!123"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ADCS ESC3 Lab - Client Provisioning" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Client IP: $CLIENT_IP" -ForegroundColor White
Write-Host "DC IP: $DC_IP" -ForegroundColor White
Write-Host "Domain: $DOMAIN_NAME" -ForegroundColor White
Write-Host "" -ForegroundColor White

# ==============================================================================
# STEP 0: Set Hostname (Manual)
# ==============================================================================
# We do this manually to avoid Vagrant's built-in reboot loop which often hangs
$targetHostname = "ESC3-CLIENT"
$currentHostname = $env:COMPUTERNAME

if ($currentHostname -ne $targetHostname) {
    Write-Host "[STEP 0] Setting hostname to $targetHostname..." -ForegroundColor Yellow
    Rename-Computer -NewName $targetHostname -Force
    Write-Host "  [OK] Hostname change scheduled. Reboot required." -ForegroundColor Green
    # We continue to network config, providing we don't need the new name yet.
    # Domain join below will trigger the reboot which applies BOTH changes.
} else {
    Write-Host "[STEP 0] Hostname already set to $targetHostname" -ForegroundColor Green
}


# ==============================================================================
# STEP 1: Configure Network and DNS
# ==============================================================================

Write-Host "[STEP 1] Configuring network and DNS..." -ForegroundColor Yellow
try {
    # Find the correct adapter (HostOnly) - Exclude NAT (10.0.2.x)
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}
    $adapter = $null
    
    foreach ($a in $adapters) {
        $ip = Get-NetIPAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ip.IPAddress -notlike "10.0.2.*") {
            $adapter = $a
            break
        }
    }
    
    if (-not $adapter) {
        # Fallback if no specific HostOnly found (maybe only 1 adapter?)
        Write-Host "  [WARN] Could not identify non-NAT adapter. Using first available." -ForegroundColor Yellow
        $adapter = $adapters | Select-Object -First 1
    }
    
    Write-Host "  Using adapter: $($adapter.Name) ($($adapter.MacAddress))" -ForegroundColor White
    
    # Remove existing IP
    Remove-NetIPAddress -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    
    # Set static IP
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $CLIENT_IP -PrefixLength 24 -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Static IP configured: $CLIENT_IP" -ForegroundColor Green
    
    # Set DNS to DC
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $DC_IP
    Write-Host "  [OK] DNS server set to: $DC_IP" -ForegroundColor Green
    
    # Clear DNS cache
    Clear-DnsClientCache
    Write-Host "  [OK] DNS cache cleared" -ForegroundColor Green
    
    # Wait for network to stabilize
    Start-Sleep -Seconds 5
}
catch {
    Write-Host "  [ERROR] Network configuration failed: $_" -ForegroundColor Red
    exit 1
}

# ==============================================================================
# STEP 2: Verify DC Reachability
# ==============================================================================

Write-Host "[STEP 2] Verifying DC connectivity..." -ForegroundColor Yellow

# Test DNS resolution
try {
    Write-Host "  Testing DNS resolution for $DOMAIN_NAME..." -ForegroundColor White
    $dnsResult = Resolve-DnsName -Name $DOMAIN_NAME -Server $DC_IP -ErrorAction Stop
    
    if ($dnsResult) {
        Write-Host "  [OK] DNS resolution successful" -ForegroundColor Green
        Write-Host "      Domain resolves to: $($dnsResult[0].IPAddress)" -ForegroundColor White
    }
}
catch {
    Write-Host "  [WARN] DNS resolution failed: $_" -ForegroundColor Yellow
    Write-Host "  [INFO] Continuing anyway - DC may not be fully ready" -ForegroundColor Yellow
}

# Test connectivity
try {
    Write-Host "  Testing connectivity to DC ($DC_IP)..." -ForegroundColor White
    $pingResult = Test-Connection -ComputerName $DC_IP -Count 2 -Quiet
    
    if ($pingResult) {
        Write-Host "  [OK] DC is reachable" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARN] Ping failed but continuing..." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARN] Connectivity test failed: $_" -ForegroundColor Yellow
}

# ==============================================================================
# STEP 2.5: Synchronize Time (Critical for Kerberos)
# ==============================================================================

Write-Host "[STEP 2.5] Synchronizing time with DC..." -ForegroundColor Yellow
try {
    # Configure time source
    w32tm /config /manualpeerlist:"$DC_IP" /syncfromflags:manual /reliable:YES /update
    Stop-Service w32time
    Start-Service w32time
    w32tm /resync /rediscover
    Write-Host "  [OK] Time synchronized" -ForegroundColor Green
}
catch {
    Write-Host "  [WARN] Time sync failed: $_" -ForegroundColor Yellow
}

# ==============================================================================
# STEP 3: Join Domain
# ==============================================================================

Write-Host "[STEP 3] Joining domain..." -ForegroundColor Yellow

# Check if already domain-joined
$computerSystem = Get-CimInstance Win32_ComputerSystem
if ($computerSystem.PartOfDomain) {
    Write-Host "  [SKIP] Computer is already domain-joined" -ForegroundColor Yellow
    Write-Host "      Current domain: $($computerSystem.Domain)" -ForegroundColor White
}
else {
    try {
        # Create credential
        $securePassword = ConvertTo-SecureString $DOMAIN_ADMIN_PASSWORD -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($DOMAIN_ADMIN_USER, $securePassword)
        
        Write-Host "  Initiating domain join to: $DOMAIN_NAME" -ForegroundColor White
        Write-Host "  Using credentials: $DOMAIN_ADMIN_USER" -ForegroundColor White
        Write-Host "  IMPORTANT: Using DNS auto-discovery (no -Server parameter)" -ForegroundColor Yellow
        
        # Join domain WITHOUT -Server parameter (ESC2 lesson learned)
        # This allows DNS auto-discovery to find the DC
        Add-Computer -DomainName $DOMAIN_NAME `
            -Credential $credential `
            -Force `
            -Restart `
            -ErrorAction Stop
        
        # This line won't execute due to restart
        Write-Host "  [OK] Domain join initiated - restarting..." -ForegroundColor Green
    }
    catch {
        Write-Host "  [ERROR] Domain join failed: $_" -ForegroundColor Red
        Write-Host "" -ForegroundColor White
        Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "1. Verify DC is fully provisioned and AD DS is running" -ForegroundColor White
        Write-Host "2. Check DNS resolution: Resolve-DnsName $DOMAIN_NAME" -ForegroundColor White
        Write-Host "3. Verify network connectivity: Test-Connection $DC_IP" -ForegroundColor White
        Write-Host "4. Manual join: Add-Computer -DomainName $DOMAIN_NAME -Credential (Get-Credential) -Force -Restart" -ForegroundColor White
        exit 1
    }
}

# ==============================================================================
# STEP 4: Configure WinRM (Post-Reboot)
# ==============================================================================

Write-Host "[STEP 4] Configuring WinRM..." -ForegroundColor Yellow
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
    }
    
    # Configure WinRM
    winrm quickconfig -quiet -force
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
    Restart-Service WinRM -Force
    
    Write-Host "  [OK] WinRM configured" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] WinRM configuration failed: $_" -ForegroundColor Red
}

# ==============================================================================
# Completion Summary
# ==============================================================================

Write-Host "" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green
Write-Host "Client Provisioning Completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Client IP: $CLIENT_IP" -ForegroundColor White
Write-Host "Domain: $DOMAIN_NAME (expected)" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "NEXT: Wait for restart, then verify domain join" -ForegroundColor Yellow
Write-Host "  vagrant powershell client -c \"Get-ComputerInfo | Select CsDomain\"" -ForegroundColor White
Write-Host "" -ForegroundColor White
