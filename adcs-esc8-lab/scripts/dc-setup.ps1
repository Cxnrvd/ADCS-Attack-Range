# ==============================================================================
# Step 2: Install AD DS
# ==============================================================================

# Variables from Vagrant
$DOMAIN_NAME    = $env:DOMAIN_NAME
$DOMAIN_NETBIOS = $env:DOMAIN_NETBIOS
$ADMIN_PASSWORD = "P@ssw0rd!123"
$SAFE_MODE_PASSWORD = ConvertTo-SecureString "SafeMode@2025!" -AsPlainText -Force

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Step 2: AD DS Installation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if already a Domain Controller
$computerSystem = Get-CimInstance Win32_ComputerSystem
if ($computerSystem.DomainRole -ge 4) {
    Write-Host "   [SKIP] Server is already a Domain Controller" -ForegroundColor Green
    exit 0
}

# ==============================================================================
# STEP 1: PRE-FLIGHT (Firewall & Network)
# ==============================================================================
# Critical: Ensure WinRM works after promotion to DC
Write-Host "  Configuring firewall and network profile..." -ForegroundColor White
try {
    # 1. Force network profile to Private (allows WinRM)
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
    
    # 2. Add Firewall Rule for WinRM (TCP 5985) if missing
    if (-not (Get-NetFirewallRule -DisplayName "Allow WinRM HTTP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Allow WinRM HTTP" -Direction Inbound -LocalPort 5985 `
                            -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    [OK] Firewall rule created." -ForegroundColor Green
    }
} catch {
    Write-Host "    [WARN] Firewall config issue (non-fatal): $_" -ForegroundColor Yellow
}

try {
    Write-Host "   Installing AD-Domain-Services feature..." -ForegroundColor White
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop | Out-Null

    Write-Host "   Setting local Administrator password..." -ForegroundColor White
    $adminUser = [ADSI]"WinNT://./Administrator,user"
    $adminUser.SetPassword($ADMIN_PASSWORD)
    $adminUser.SetInfo()

    Write-Host "   Promoting to Domain Controller ($DOMAIN_NAME)..." -ForegroundColor White
    Write-Host "   NOTE: This process will automatically reboot the server." -ForegroundColor Yellow
    
    # This command triggers the reboot automatically upon success
    Install-ADDSForest `
        -DomainName $DOMAIN_NAME `
        -DomainNetbiosName $DOMAIN_NETBIOS `
        -DomainMode WinThreshold `
        -ForestMode WinThreshold `
        -SafeModeAdministratorPassword $SAFE_MODE_PASSWORD `
        -InstallDns `
        -Force `
        -NoRebootOnCompletion:$true
}
catch {
    Write-Host "   [ERROR] AD DS installation failed: $_" -ForegroundColor Red
    exit 1
}

exit 0
