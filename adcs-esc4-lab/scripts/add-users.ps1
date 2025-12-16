# ==============================================================================
# ADCS ESC4 Lab - Add Users Script (Unique Passwords)
# ==============================================================================

$DOMAIN_NETBIOS = "ADCS"

# Password Policy: Complex, No User Name in Password
$USERS = @{
    "johndoe"      = "Summer2024!"
    "janesmith"    = "Winter2024!"
    "alicejohnson" = "Spring2024!"
    "bobwilliams"  = "Autumn2024!"
    "charliebrown" = "Coffee2024!"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Adding/Updating ESC4 Lab Users" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($user in $USERS.GetEnumerator()) {
    $username = $user.Key
    $passwordPlain = $user.Value
    $passwordSecure = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

    try {
        if (Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue) {
            Write-Host "  [UPDATE] User $username exists. Updating password..." -ForegroundColor Yellow
            Set-ADAccountPassword -Identity $username -NewPassword $passwordSecure -Reset -ErrorAction Stop
            Set-ADUser -Identity $username -Enabled $true -PasswordNeverExpires $true
            Write-Host "  [OK] Password updated for $username" -ForegroundColor Green
        }
        else {
            New-ADUser -Name $username `
                -SamAccountName $username `
                -UserPrincipalName "${username}@adcs.local" `
                -AccountPassword $passwordSecure `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Confirm:$false `
                -ErrorAction Stop
            
            Write-Host "  [OK] User created: $username" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [ERROR] Failed to process ${username}: $_" -ForegroundColor Red
    }
}

Write-Host "" -ForegroundColor White
Write-Host "User provisioning complete." -ForegroundColor Green
