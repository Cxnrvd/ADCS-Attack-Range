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
        -NoRebootOnCompletion:$false
}
catch {
    Write-Host "   [ERROR] AD DS installation failed: $_" -ForegroundColor Red
    exit 1
}

exit 0