# ==============================================================================
# Client Provisioning
# ==============================================================================
$DC_IP       = $env:DC_IP
$DOMAIN_NAME = $env:DOMAIN_NAME

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Client Provisioning" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Set DNS
Write-Host "   Setting DNS to $DC_IP..." -ForegroundColor Yellow
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
if ($adapter) {
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $DC_IP
    Write-Host "   [OK] DNS set." -ForegroundColor Green
}

# 2. Join Domain
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-Host "   [SKIP] Already joined to domain." -ForegroundColor Green
}
else {
    Write-Host "   Joining domain $DOMAIN_NAME..." -ForegroundColor Yellow
    
    # Wait for DNS resolution
    try { Resolve-DnsName $DOMAIN_NAME -ErrorAction Stop | Out-Null } 
    catch { Write-Host "   [ERROR] Cannot resolve domain. Check DC." -ForegroundColor Red; exit 1 }

    $cred = New-Object System.Management.Automation.PSCredential("ADCS\Administrator", (ConvertTo-SecureString "P@ssw0rd!123" -AsPlainText -Force))
    try {
        Add-Computer -DomainName $DOMAIN_NAME -Credential $cred -Force -Restart
        # Script ends here as computer restarts
    }
    catch {
        Write-Host "   [ERROR] Domain join failed: $_" -ForegroundColor Red
        exit 1
    }
}
