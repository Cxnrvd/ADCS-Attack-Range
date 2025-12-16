# ==============================================================================
# ADCS ESC4 Lab - Client Provisioning (SAFE)
# ==============================================================================

$DC_IP       = $env:DC_IP
$DOMAIN_NAME = $env:DOMAIN_NAME

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ADCS ESC4 Lab - Client Provisioning" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ==============================================================================
# STEP 1: Force DNS to DC (SAFE – does not kill WinRM)
# ==============================================================================
Write-Host "[STEP 1] Setting DNS server to DC..." -ForegroundColor Yellow

$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
if ($adapter) {
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $DC_IP
    Write-Host "  [OK] DNS set on $($adapter.Name)" -ForegroundColor Green
}

Start-Sleep -Seconds 10

# ==============================================================================
# STEP 2: Verify DC connectivity
# ==============================================================================
Write-Host "[STEP 2] Verifying DC connectivity..." -ForegroundColor Yellow

Resolve-DnsName $DOMAIN_NAME -ErrorAction Stop | Out-Null
Write-Host "  [OK] DNS resolution successful" -ForegroundColor Green

# ==============================================================================
# STEP 3: Join Domain (EXPECTED REBOOT)
# ==============================================================================
Write-Host "[STEP 3] Joining domain..." -ForegroundColor Yellow

$sys = Get-CimInstance Win32_ComputerSystem

if (-not $sys.PartOfDomain) {

    $password   = ConvertTo-SecureString "P@ssw0rd!123" -AsPlainText -Force
    $credential = New-Object PSCredential("ADCS\Administrator", $password)

    Add-Computer `
        -DomainName $DOMAIN_NAME `
        -Credential $credential `
        -Force `
        -Restart

    Write-Host "  [OK] Domain join initiated and done - rebooting" -ForegroundColor Green
}
else {
    Write-Host "  [SKIP] Already domain joined" -ForegroundColor Yellow
}

