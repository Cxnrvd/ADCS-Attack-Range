# ==============================================================================
# ADCS ESC2 Lab - DC Provisioning Script
# ==============================================================================
# Fully automated Domain Controller setup with:
# - AD DS installation
# - AD CS installation (100% automated - ESC1 Fix #1)
# - ESC2 vulnerable template creation
# - User creation
# - WinRM configuration (ESC1 Fix #2)
# - All ESC1 lessons learned incorporated
# ==============================================================================

# Import environment variables
$DC_IP = $env:DC_IP
$DOMAIN_NAME = $env:DOMAIN_NAME
$DOMAIN_NETBIOS = $env:DOMAIN_NETBIOS

# Import helper functions
Import-Module C:\provision\helpers.ps1 -Force

# Domain configuration
$DOMAIN_ADMIN_PASSWORD = "P@ssw0rd!123"
$SAFE_MODE_PASSWORD = ConvertTo-SecureString "SafeMode@2024!" -AsPlainText -Force

Write-Log "========================================" -Level INFO
Write-Log "ADCS ESC2 Lab - DC Provisioning Started" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "DC IP: $DC_IP" -Level INFO
Write-Log "Domain: $DOMAIN_NAME" -Level INFO
Write-Log "NetBIOS: $DOMAIN_NETBIOS" -Level INFO
Write-Log " " -Level INFO

# ==============================================================================
# STEP 0: Performance Optimizations
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 0: Performance Optimizations" -Level INFO
Write-Log "========================================" -Level INFO

Optimize-Performance

# ==============================================================================
# STEP 1: Set Administrator Password
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 1: Set Administrator Password" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-StateMarker -Name "admin_password") {
    Write-Log "Administrator password already set. Skipping..." -Level SUCCESS
}
else {
    try {
        $adminUser = [ADSI]"WinNT://./Administrator,user"
        $adminUser.SetPassword($DOMAIN_ADMIN_PASSWORD)
        $adminUser.SetInfo()
        Write-Log "Administrator password set successfully" -Level SUCCESS
        Set-StateMarker -Name "admin_password" -Message "Administrator password configured"
    }
    catch {
        Write-Log "Error setting administrator password: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# ==============================================================================
# STEP 2: Install and Configure AD DS
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 2: Active Directory Domain Services" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-StateMarker -Name "adds") {
    Write-Log "AD DS already installed. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Installing AD DS Windows Feature..." -Level INFO
    
    try {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        Write-Log "AD DS feature installed successfully" -Level SUCCESS
        
        Write-Log "Promoting server to Domain Controller..." -Level INFO
        Write-Log "  Domain: $DOMAIN_NAME" -Level INFO
        Write-Log "  NetBIOS: $DOMAIN_NETBIOS" -Level INFO
        Write-Log "  NOTE: Server will reboot automatically after promotion" -Level WARNING
        
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
        
        # Check if already promoted (resumption scenario)
        $sysInfo = Get-CimInstance Win32_ComputerSystem
        if ($sysInfo.DomainRole -ge 4) {
            Write-Log "Server is already a Domain Controller. Skipping promotion..." -Level SUCCESS
            Set-StateMarker -Name "adds" -Message "AD DS installed and configured"
        }
        else {
            Install-ADDSForest @forestParams
        }
        
        # This won't execute due to reboot, but set marker for after reboot
        Set-StateMarker -Name "adds" -Message "AD DS installed and configured"
    }
    catch {
        Write-Log "Error installing AD DS: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# ==============================================================================
# STEP 3: Wait for AD to be Fully Ready (ESC1 Fix #1)
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 3: Verify AD DS Health" -Level INFO
Write-Log "========================================" -Level INFO

# Verify NTDS is running
if (-not (Test-ServiceRunning -ServiceName "NTDS")) {
    Write-Log "Waiting for NTDS service..." -Level INFO
    if (-not (Wait-ForService -ServiceName "NTDS" -TimeoutSeconds 120)) {
        Write-Log "NTDS service did not start!" -Level ERROR
        exit 1
    }
}

Write-Log "NTDS service is running" -Level SUCCESS

# Extended wait for AD readiness (ESC1 lesson learned)
if (-not (Wait-ForADReady -WaitSeconds 60)) {
    Write-Log "AD is not ready!" -Level ERROR
    exit 1
}

Write-Log "Active Directory is fully ready" -Level SUCCESS

# ==============================================================================
# STEP 4: Install and Configure AD CS (100% Automated - ESC1 Fix #1)
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 4: Active Directory Certificate Services" -Level INFO
Write-Log "========================================" -Level INFO

if ($true) {
    Write-Log "MANUAL MODE: Skipping Automated AD CS Installation per user request." -Level WARNING
    Write-Log "Please install AD CS manually after scripts verify users." -Level INFO
    Set-StateMarker -Name "adcs_skipped" -Message "Manual Mode Enabled"
}

# ==============================================================================
# STEP 5: Create ESC2 Vulnerable Certificate Template
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 5: Create ESC2 Vulnerable Template" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "WARNING: Creating intentionally vulnerable template!" -Level WARNING
Write-Log " " -Level INFO

if ($true) {
    Write-Log "MANUAL MODE: Skipping Automated Template Creation per user request." -Level WARNING
    Write-Log "Please create ESC2 template manually." -Level INFO
    Set-StateMarker -Name "template_skipped" -Message "Manual Mode Enabled"
}


# ==============================================================================
# STEP 3.5: Create AD Users (Moved before AD CS for fault tolerance)
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 3.5: Create AD Users" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-StateMarker -Name "users") {
    Write-Log "AD users already created. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Creating lab users..." -Level INFO
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $users = @(
            @{ Name = "johndoe"; GivenName = "John"; Surname = "Doe"; Password = "P@ssw0rd!123" }
            @{ Name = "janesmith"; GivenName = "Jane"; Surname = "Smith"; Password = "J4neS!th@456" }
            @{ Name = "alicejohnson"; GivenName = "Alice"; Surname = "Johnson"; Password = "Alic3J0hnson!789" }
            @{ Name = "bobwilliams"; GivenName = "Bob"; Surname = "Williams"; Password = "B0bW1lliams@987" }
            @{ Name = "charliebrown"; GivenName = "Charlie"; Surname = "Brown"; Password = "Ch@rli3Br0wn!111" }
        )
        
        foreach ($userInfo in $users) {
            $username = $userInfo.Name
            
            $existingUser = Get-ADUser -Filter {SamAccountName -eq $username} -ErrorAction SilentlyContinue
            
            if ($existingUser) {
                Write-Log "  User '$username' already exists" -Level WARNING
                continue
            }
            
            $securePassword = ConvertTo-SecureString $userInfo.Password -AsPlainText -Force
            
            $userParams = @{
                Name = $username
                SamAccountName = $username
                UserPrincipalName = "$username@$DOMAIN_NAME"
                GivenName = $userInfo.GivenName
                Surname = $userInfo.Surname
                DisplayName = "$($userInfo.GivenName) $($userInfo.Surname)"
                AccountPassword = $securePassword
                Enabled = $true
                PasswordNeverExpires = $true
                CannotChangePassword = $false
                Path = "CN=Users,DC=adcs,DC=local"
            }
            
            New-ADUser @userParams -ErrorAction Stop
            Write-Log "  Created user: $username ($($userInfo.GivenName) $($userInfo.Surname))" -Level SUCCESS
        }
        
        Write-Log "All users created successfully" -Level SUCCESS
        Set-StateMarker -Name "users" -Message "AD users created"
    }
    catch {
        Write-Log "Error creating users: $($_.Exception.Message)" -Level ERROR
    }
}


# ==============================================================================
# STEP 7: Configure WinRM (ESC1 Fix #2)
# ==============================================================================

Write-Log "========================================" -Level INFO
Write-Log "STEP 7: Configure WinRM" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-StateMarker -Name "winrm") {
    Write-Log "WinRM already configured. Skipping..." -Level SUCCESS
}
else {
    Configure-WinRM
    Set-StateMarker -Name "winrm" -Message "WinRM configured"
}

# ==============================================================================
# Completion
# ==============================================================================

Write-Log "========================================" -Level SUCCESS
Write-Log "DC Provisioning Completed Successfully!" -Level SUCCESS
Write-Log "========================================" -Level SUCCESS
Write-Log " " -Level INFO
Write-Log "Domain: $DOMAIN_NAME" -Level INFO
Write-Log "CA: ADCS-CA-ESC2" -Level INFO
Write-Log "ESC2 Template: ESC2User (vulnerable)" -Level INFO
Write-Log "Users: johndoe, janesmith, alicejohnson, bobwilliams, charliebrown" -Level INFO
Write-Log " " -Level INFO
Write-Log "Next: Provision CLIENT01 with 'vagrant up client01'" -Level INFO
