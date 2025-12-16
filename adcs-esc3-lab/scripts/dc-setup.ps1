# ==============================================================================
# ADCS ESC3 Lab - Domain Controller Setup Script
# ==============================================================================
# This script installs AD DS ONLY. CA installation is manual.
# ==============================================================================

# Import environment variables
$DC_IP = $env:DC_IP
$DOMAIN_NAME = $env:DOMAIN_NAME
$DOMAIN_NETBIOS = $env:DOMAIN_NETBIOS

# Configuration
$ADMIN_PASSWORD = "P@ssw0rd!123"
$SAFE_MODE_PASSWORD = ConvertTo-SecureString "SafeMode@2024!" -AsPlainText -Force

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ADCS ESC3 Lab - DC Provisioning" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Domain: $DOMAIN_NAME" -ForegroundColor White
Write-Host "NetBIOS: $DOMAIN_NETBIOS" -ForegroundColor White
Write-Host "DC IP: $DC_IP" -ForegroundColor White
Write-Host "" -ForegroundColor White

# ==============================================================================
# STEP 1: Set Administrator Password
# ==============================================================================

Write-Host "[STEP 1] Setting Administrator password..." -ForegroundColor Yellow
try {
    $adminUser = [ADSI]"WinNT://./Administrator,user"
    $adminUser.SetPassword($ADMIN_PASSWORD)
    $adminUser.SetInfo()
    Write-Host "  [OK] Administrator password set" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to set password: $_" -ForegroundColor Red
    exit 1
}

# ==============================================================================
# STEP 2: Configure Network
# ==============================================================================

Write-Host "[STEP 2] Configuring static IP..." -ForegroundColor Yellow
try {
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1
    
    # Remove existing IP
    Remove-NetIPAddress -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    
    # Set static IP
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $DC_IP -PrefixLength 24 -ErrorAction Stop | Out-Null
    
    # Set DNS to self
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $DC_IP
    
    Write-Host "  [OK] Static IP configured: $DC_IP" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Network configuration failed: $_" -ForegroundColor Red
    exit 1
}

# ==============================================================================
# STEP 3: Install AD DS
# ==============================================================================

Write-Host "[STEP 3] Installing AD DS..." -ForegroundColor Yellow

# Check if already a DC
$computerSystem = Get-CimInstance Win32_ComputerSystem
if ($computerSystem.DomainRole -ge 4) {
    Write-Host "  [SKIP] Server is already a Domain Controller" -ForegroundColor Yellow
}
else {
    try {
        # Install AD DS feature
        Write-Host "  Installing AD DS feature..." -ForegroundColor White
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop | Out-Null
        Write-Host "  [OK] AD DS feature installed" -ForegroundColor Green
        
        # Promote to DC
        Write-Host "  Promoting to Domain Controller..." -ForegroundColor White
        Write-Host "  NOTE: Server will reboot automatically" -ForegroundColor Yellow
        
        $forestParams = @{
            DomainName = $DOMAIN_NAME
            DomainNetBiosName = $DOMAIN_NETBIOS
            DomainMode = 'WinThreshold'
            ForestMode = 'WinThreshold'
            SafeModeAdministratorPassword = $SAFE_MODE_PASSWORD
            InstallDns = $true
            NoRebootOnCompletion = $false
            Force = $true
        }
        
        Install-ADDSForest @forestParams
        
        # This line won't execute due to reboot
        Write-Host "  [OK] DC promotion initiated" -ForegroundColor Green
    }
    catch {
        Write-Host "  [ERROR] AD DS installation failed: $_" -ForegroundColor Red
        exit 1
    }
}

# ==============================================================================
# STEP 4: Wait for AD to be Ready (Post-Reboot)
# ==============================================================================

Write-Host "[STEP 4] Verifying AD DS health..." -ForegroundColor Yellow

# Wait for NTDS service
$ntds = Get-Service -Name NTDS -ErrorAction SilentlyContinue
if ($ntds) {
    $timeout = 120
    $elapsed = 0
    while ($ntds.Status -ne 'Running' -and $elapsed -lt $timeout) {
        Start-Sleep -Seconds 5
        $elapsed += 5
        $ntds = Get-Service -Name NTDS
        Write-Host "  Waiting for NTDS... ($elapsed/$timeout)" -ForegroundColor White
    }
    
    if ($ntds.Status -eq 'Running') {
        Write-Host "  [OK] NTDS service is running" -ForegroundColor Green
    }
    else {
        Write-Host "  [ERROR] NTDS service did not start" -ForegroundColor Red
        exit 1
    }
}

# Extended wait for AD
Write-Host "  Waiting for AD to be fully ready..." -ForegroundColor White
Start-Sleep -Seconds 60

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain
    Write-Host "  [OK] Domain: $($domain.DNSRoot)" -ForegroundColor Green
    Write-Host "  [OK] Functional Level: $($domain.DomainMode)" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] AD verification failed: $_" -ForegroundColor Red
}

# ==============================================================================
# STEP 5: Configure WinRM
# ==============================================================================

Write-Host "[STEP 5] Configuring WinRM..." -ForegroundColor Yellow
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
Write-Host "DC Provisioning Completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Domain: $DOMAIN_NAME" -ForegroundColor White
Write-Host "DC IP: $DC_IP" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Manually install AD CS (Certificate Authority)" -ForegroundColor White
Write-Host "2. Manually create ESC3 vulnerable template" -ForegroundColor White
Write-Host "3. Provision client machine: vagrant up client" -ForegroundColor White
Write-Host "" -ForegroundColor White
