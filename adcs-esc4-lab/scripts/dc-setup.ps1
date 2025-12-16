# ==============================================================================
# ADCS ESC4 Lab - DC Setup Script (WinRM-SAFE)
# ==============================================================================

$DOMAIN_NAME    = $env:DOMAIN_NAME
$DOMAIN_NETBIOS = $env:DOMAIN_NETBIOS

$ADMIN_PASSWORD = "P@ssw0rd!123"
$SAFE_MODE_PASSWORD = ConvertTo-SecureString "SafeMode@2024!" -AsPlainText -Force
$TARGET_HOSTNAME = "ESC4-DC"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ADCS ESC4 Lab - DC Provisioning" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ==============================================================================
# STEP 0: Set Hostname
# ==============================================================================
if ($env:COMPUTERNAME -ne $TARGET_HOSTNAME) {
    Write-Host "[STEP 0] Setting hostname to $TARGET_HOSTNAME..." -ForegroundColor Yellow
    Rename-Computer -NewName $TARGET_HOSTNAME -Force
    Write-Host "  [OK] Hostname change scheduled (reboot pending)" -ForegroundColor Green
}

Write-Host "[INFO] Network configuration handled by Vagrant" -ForegroundColor Cyan

# ==============================================================================
# STEP 1: Ensure WinRM is running (NO reconfiguration)
# ==============================================================================
Write-Host "[STEP 1] Ensuring WinRM service is running..." -ForegroundColor Yellow
Start-Service WinRM

# ==============================================================================
# STEP 2: Install AD DS
# ==============================================================================
Write-Host "[STEP 2] Installing AD DS..." -ForegroundColor Yellow

$computerSystem = Get-CimInstance Win32_ComputerSystem
if ($computerSystem.DomainRole -ge 4) {
    Write-Host "  [SKIP] Server is already a Domain Controller" -ForegroundColor Yellow
    exit 0
}

try {
    Write-Host "  Installing AD DS feature..." -ForegroundColor White
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop | Out-Null

    # Set local Administrator password
    $adminUser = [ADSI]"WinNT://./Administrator,user"
    $adminUser.SetPassword($ADMIN_PASSWORD)
    $adminUser.SetInfo()

    Write-Host "  Promoting to Domain Controller..." -ForegroundColor White
    Write-Host "  NOTE: Server will reboot automatically" -ForegroundColor Yellow

    Install-ADDSForest `
        -DomainName $DOMAIN_NAME `
        -DomainNetbiosName $DOMAIN_NETBIOS `
        -DomainMode WinThreshold `
        -ForestMode WinThreshold `
        -SafeModeAdministratorPassword $SAFE_MODE_PASSWORD `
        -InstallDns `
        -Force `
        -NoRebootOnCompletion

    Write-Host "  [OK] AD DS Installed. Rebooting..." -ForegroundColor Green
    Start-Sleep 5
    shutdown /r /t 5
    exit 0
}
catch {
    Write-Host "  [ERROR] AD DS installation failed: $_" -ForegroundColor Red
    exit 1
}
