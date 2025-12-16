# ADCS ESC2 Lab - Automated VirtualBox Console Provisioning
# Bypasses WinRM by using VBoxManage guestcontrol

param(
    [string]$VMName = "ESC2-DC",
    [string]$Username = "vagrant",
    [string]$Password = "vagrant"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================"
Write-Host "Automated VBoxManage Provisioning"
Write-Host "========================================"
Write-Host ""

# Check if VM is running
Write-Host "Checking VM status..." -ForegroundColor Cyan
$vmStatus = & VBoxManage showvminfo $VMName --machinereadable | Select-String "VMState="
if ($vmStatus -notmatch "running") {
    Write-Host "ERROR: VM is not running" -ForegroundColor Red
    exit 1
}
Write-Host "VM is running" -ForegroundColor Green

# Copy provision scripts to VM
Write-Host ""
Write-Host "Copying provision scripts to VM..." -ForegroundColor Cyan

$scriptsPath = "$PSScriptRoot\provision"
$scripts = @("helpers.ps1", "dc-provision.ps1")

foreach ($script in $scripts) {
    $localPath = Join-Path $scriptsPath $script
    Write-Host "  Copying $script..." -ForegroundColor White
    
    & VBoxManage guestcontrol $VMName copyto --username $Username --password $Password $localPath "C:\Scripts\$script" --target-directory "C:\Scripts"
        
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Failed to copy $script" -ForegroundColor Red
        continue
    }
    Write-Host "  Copied $script successfully" -ForegroundColor Green
}

# Execute provision script in VM
Write-Host ""
Write-Host "Executing dc-provision.ps1 in VM..." -ForegroundColor Cyan
Write-Host "This will take 20-25 minutes..." -ForegroundColor Yellow
Write-Host ""

& VBoxManage guestcontrol $VMName run --username $Username --password $Password --exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" --wait-stdout --wait-stderr -- -ExecutionPolicy Bypass -File "C:\Scripts\dc-provision.ps1"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Provisioning Completed Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Provisioning Failed (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
