# ==============================================================================
# Step 1: Set Hostname
# ==============================================================================
$TARGET_HOSTNAME = "ESC8-DC"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Step 1: Hostname Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($env:COMPUTERNAME -ne $TARGET_HOSTNAME) {
    Write-Host "   Current Hostname: $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host "   Target Hostname:  $TARGET_HOSTNAME" -ForegroundColor Yellow
    Write-Host "   Changing hostname..." -ForegroundColor White
    
    try {
        Rename-Computer -NewName $TARGET_HOSTNAME -Force -ErrorAction Stop
        Write-Host "   [SUCCESS] Hostname changed. Reboot required." -ForegroundColor Green
        # Vagrant detects the reboot trigger automatically
    }
    catch {
        Write-Host "   [ERROR] Failed to rename computer: $_" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "   [SKIP] Hostname is already set to $TARGET_HOSTNAME" -ForegroundColor Green
}
