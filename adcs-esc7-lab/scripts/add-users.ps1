# ==============================================================================
# Step 3: Add Users (WinRM Safe)
# ==============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Step 3: User Provisioning" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Wait for Active Directory Web Services to be fully ready
Write-Host "   Waiting for Active Directory to be ready..." -ForegroundColor Yellow
$maxRetries = 60
$retryCount = 0
$adReady = $false

while (-not $adReady -and $retryCount -lt $maxRetries) {
    try {
        $null = Get-ADDomain -ErrorAction Stop
        $adReady = $true
    }
    catch {
        Start-Sleep 5
        $retryCount++
        Write-Host "." -NoNewline
    }
}
Write-Host ""

if (-not $adReady) {
    Write-Host "   [ERROR] AD services not responding after wait." -ForegroundColor Red
    exit 1
}

# 2. Create Users
$USERS = @{
    "johndoe"      = "Summer2024!"
    "janesmith"    = "Winter2024!"
    "alicejohnson" = "Spring2024!"
    "bobwilliams"  = "Autumn2024!"
    "charliebrown" = "Coffee2024!"
}

foreach ($u in $USERS.GetEnumerator()) {
    $name = $u.Key
    $pass = ConvertTo-SecureString $u.Value -AsPlainText -Force
    
    try {
        if (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue) {
            Write-Host "   [SKIP] User '$name' already exists." -ForegroundColor Green
        }
        else {
            New-ADUser -Name $name -SamAccountName $name -AccountPassword $pass -Enabled $true -PasswordNeverExpires $true -ErrorAction Stop
            Write-Host "   [CREATE] User '$name' created." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "   [ERROR] Failed to create '$name': $_" -ForegroundColor Red
    }
}
