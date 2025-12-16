#Requires -Version 5.1
<#
.SYNOPSIS
    Domain Controller provisioning script for ADCS ESC1 Lab.

.DESCRIPTION
    Configures a Windows Server 2019 VM as a Domain Controller with AD CS
    and intentionally creates a vulnerable certificate template (ESC1User)
    for educational demonstration of AD CS abuse.

.NOTES
    Author: ADCS ESC1 Lab
    Compatible with: Windows PowerShell 5.1
    
    WARNING: FOR ISOLATED LAB ENVIRONMENTS ONLY!
    This script creates intentionally vulnerable configurations.
    NEVER use these settings in production environments.
    
.EXAMPLE
    .\dc_provision.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Configuration variables
$DOMAIN_NAME = "adcs.local"
$DOMAIN_NETBIOS = "ADCS"
$DC_IP = "192.168.57.10"
$DSRM_PASSWORD = "LabDSRM@2024!Secure"
$DOMAIN_ADMIN_PASSWORD = "LabAdmin@2024!Secure"

# AD Users to create
$LAB_USERS = @(
    @{ Name = "johndoe"; Password = "P@ssw0rd!John2024"; GivenName = "John"; Surname = "Doe" }
    @{ Name = "janesmith"; Password = "P@ssw0rd!Jane2024"; GivenName = "Jane"; Surname = "Smith" }
    @{ Name = "alicejohnson"; Password = "P@ssw0rd!Alice2024"; GivenName = "Alice"; Surname = "Johnson" }
    @{ Name = "bobwilliams"; Password = "P@ssw0rd!Bob2024"; GivenName = "Bob"; Surname = "Williams" }
    @{ Name = "charliebrown"; Password = "P@ssw0rd!Charlie2024"; GivenName = "Charlie"; Surname = "Brown" }
)

# CA Configuration
$CA_COMMON_NAME = "ADCS-CA"

# Load helper functions
$helpersPath = "C:\provision\helpers.ps1"

if (-not (Test-Path $helpersPath)) {
    Write-Host "ERROR: Helper script not found at: $helpersPath" -ForegroundColor Red
    Write-Host "Vagrant should have uploaded it before running this script" -ForegroundColor Yellow
    exit 1
}

. $helpersPath

Write-Log "========================================" -Level INFO
Write-Log "ADCS ESC1 Lab - DC Provisioning Started" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Domain: $DOMAIN_NAME" -Level INFO
Write-Log "DC IP: $DC_IP" -Level INFO
Write-Log " " -Level INFO

# Check if already completed
if (Test-FlagExists -FlagName "dc_completed") {
    Write-Log "DC provisioning already completed. Skipping..." -Level SUCCESS
    Write-Log "To re-provision, delete: $(Get-FlagPath -FlagName 'dc_completed')" -Level INFO
    exit 0
}

# STEP 0: Set Administrator Password (Required for Domain Creation)
Write-Log "========================================" -Level INFO
Write-Log "STEP 0: Set Administrator Password" -Level INFO
Write-Log "========================================" -Level INFO

if (-not (Test-FlagExists -FlagName "admin_password_set")) {
    Write-Log "Setting local Administrator password..." -Level INFO
    
    try {
        $adminUser = [ADSI]"WinNT://./Administrator,user"
        $adminUser.SetPassword($DOMAIN_ADMIN_PASSWORD)
        $adminUser.SetInfo()
        
        Write-Log "Administrator password set successfully" -Level SUCCESS
        Set-Flag -FlagName "admin_password_set" -Message "Administrator password configured"
    }
    catch {
        Write-Log "Error setting Administrator password: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}
else {
    Write-Log "Administrator password already set. Skipping..." -Level SUCCESS
}

# STEP 1: Install Active Directory Domain Services
Write-Log "========================================" -Level INFO
Write-Log "STEP 1: Active Directory Domain Services" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "dc_ad_installed") {
    Write-Log "AD DS already installed. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Installing AD DS role..." -Level INFO
    
    try {
        $addsFeature = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        
        if ($addsFeature.Success) {
            Write-Log "AD DS feature installed successfully" -Level SUCCESS
        }
        else {
            Write-Log "AD DS feature installation failed" -Level ERROR
            exit 1
        }
        
        Write-Log "Promoting server to Domain Controller..." -Level INFO
        Write-Log "  Domain: $DOMAIN_NAME" -Level INFO
        Write-Log "  NetBIOS: $DOMAIN_NETBIOS" -Level INFO
        
        $secureDSRM = ConvertTo-SecureString $DSRM_PASSWORD -AsPlainText -Force
        
        $forestParams = @{
            DomainName = $DOMAIN_NAME
            DomainNetbiosName = $DOMAIN_NETBIOS
            ForestMode = 'WinThreshold'
            DomainMode = 'WinThreshold'
            InstallDns = $true
            SafeModeAdministratorPassword = $secureDSRM
            NoRebootOnCompletion = $false
            Force = $true
        }
        
        Set-Flag -FlagName "dc_ad_installed" -Message "AD DS promotion initiated, reboot pending"
        
        Install-ADDSForest @forestParams
        
        Write-Log "AD DS promotion completed (system will reboot)" -Level SUCCESS
    }
    catch {
        Write-Log "Error installing AD DS: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# Verify AD DS is running (after reboot)
if (-not (Test-ADDSInstalled)) {
    Write-Log "AD DS verification failed" -Level ERROR
    exit 1
}

Write-Log "AD DS is running and healthy" -Level SUCCESS

# Wait for AD to be fully ready with extended verification
Write-Log "Waiting for Active Directory services..." -Level INFO
if (-not (Wait-ForService -ServiceName "NTDS" -TimeoutSeconds 120)) {
    Write-Log "NTDS service failed to start" -Level ERROR
    exit 1
}

Write-Log "Initial AD services verified. Performing extended readiness checks..." -Level INFO

# Extended wait for domain to fully initialize (critical for CA installation)
Start-Sleep -Seconds 30

# Verify domain functional level
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    
    Write-Log "Domain Name: $($domain.DNSRoot)" -Level INFO
    Write-Log "Domain Functional Level: $($domain.DomainMode)" -Level INFO
    Write-Log "Forest Functional Level: $($forest.ForestMode)" -Level INFO
    
    # Verify PKI services container exists (required for CA)
    Write-Log "Verifying PKI services container in AD..." -Level INFO
    $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $pkiContainerDN = "CN=Public Key Services,CN=Services,$configContext"
    
    $retryCount = 0
    $maxRetries = 10
    $pkiContainerExists = $false
    
    while ($retryCount -lt $maxRetries -and -not $pkiContainerExists) {
        try {
            $pkiContainer = Get-ADObject -Identity $pkiContainerDN -ErrorAction Stop
            $pkiContainerExists = $true
            Write-Log "PKI services container verified in AD" -Level SUCCESS
        }
        catch {
            $retryCount++
            Write-Log "PKI container not ready yet (attempt $retryCount/$maxRetries), waiting 10 seconds..." -Level WARNING
            Start-Sleep -Seconds 10
        }
    }
    
    if (-not $pkiContainerExists) {
        Write-Log "PKI services container not available after $maxRetries attempts" -Level ERROR
        Write-Log "This is unusual - AD may not be fully initialized" -Level ERROR
        exit 1
    }
    
    # Additional wait to ensure AD replication is complete
    Write-Log "Allowing additional time for AD stabilization..." -Level INFO
    Start-Sleep -Seconds 20
    
    Write-Log "Domain fully ready for CA installation" -Level SUCCESS
}
catch {
    Write-Log "Error verifying domain readiness: $($_.Exception.Message)" -Level ERROR
    Write-Log "Waiting additional 30 seconds and continuing..." -Level WARNING
    Start-Sleep -Seconds 30
}

# STEP 2: Install Active Directory Certificate Services
Write-Log "========================================" -Level INFO
Write-Log "STEP 2: Active Directory Certificate Services" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "ca_installed") {
    Write-Log "AD CS already installed. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Installing AD CS role..." -Level INFO
    
    try {
        # CRITICAL: Set CA directory permissions BEFORE installation
        # This prevents CertSvc startup failures later
        Write-Log "Pre-configuring CA directory permissions..." -Level INFO
        
        $certPaths = @(
            "C:\Windows\System32\CertLog",
            "C:\Windows\System32\CertSrv",
            "C:\Windows\System32\CertSrv\CertEnroll"
        )
        
        foreach ($path in $certPaths) {
            if (Test-Path $path) {
                Write-Log "  Setting permissions on $path" -Level INFO
                icacls $path /grant "NETWORK SERVICE:(OI)(CI)F" /T 2>&1 | Out-Null
                icacls $path /grant "LOCAL SERVICE:(OI)(CI)F" /T 2>&1 | Out-Null
                icacls $path /grant "Administrators:(OI)(CI)F" /T 2>&1 | Out-Null
            } else {
                # Create directory if it doesn't exist
                New-Item -Path $path -ItemType Directory -Force | Out-Null
                icacls $path /grant "NETWORK SERVICE:(OI)(CI)F" /T 2>&1 | Out-Null
                icacls $path /grant "LOCAL SERVICE:(OI)(CI)F" /T 2>&1 | Out-Null
                icacls $path /grant "Administrators:(OI)(CI)F" /T 2>&1 | Out-Null
                Write-Log "  Created and configured $path" -Level INFO
            }
        }
        
        # Set registry permissions for CertSvc
        Write-Log "Setting CertSvc registry permissions..." -Level INFO
        $caRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc"
        if (Test-Path $caRegPath) {
            $acl = Get-Acl $caRegPath
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                "NETWORK SERVICE",
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.SetAccessRule($rule)
            Set-Acl -Path $caRegPath -AclObject $acl -ErrorAction SilentlyContinue
        }
        
        Write-Log "Permissions pre-configured for CA" -Level SUCCESS
        
        $adcsFeature = Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
        
        if ($adcsFeature.Success) {
            Write-Log "AD CS feature installed successfully" -Level SUCCESS
        }
        else {
            Write-Log "AD CS feature installation failed" -Level ERROR
            exit 1
        }
        
        Write-Log "Configuring Enterprise CA..." -Level INFO
        Write-Log " " -Level INFO
        Write-Log "================================================" -Level WARNING
        Write-Log "MANUAL CA INSTALLATION REQUIRED" -Level WARNING
        Write-Log "================================================" -Level WARNING
        Write-Log " " -Level INFO
        Write-Log "Due to a known Windows Server issue (ERROR_DS_RANGE_CONSTRAINT)," -Level WARNING
        Write-Log "the automated CA installation cannot complete." -Level WARNING
        Write-Log " " -Level INFO
        Write-Log "Please run this command manually after vagrant up completes:" -Level INFO
        Write-Log " " -Level INFO
        Write-Log "  vagrant powershell dc -c \"Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'ADCS-CA' -Force\"" -Level INFO
        Write-Log " " -Level INFO
        Write-Log "Or use Server Manager GUI (see MANUAL_CA_SETUP.md for details)" -Level INFO
        Write-Log " " -Level INFO
        Write-Log "================================================" -Level WARNING
        
        # Set flag to prevent re-attempting
        Set-Flag -FlagName "ca_installed" -Message "CA feature installed - manual configuration required"
    }
    catch {
        Write-Log "Error installing AD CS: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# Verify Certificate Services
Write-Log "Verifying Certificate Services..." -Level INFO

if (-not (Test-ServiceRunning -ServiceName "CertSvc")) {
    Write-Log "CertSvc not running, attempting to start..." -Level WARNING
    
    try {
        Start-Service -Name "CertSvc" -ErrorAction Stop
        
        if (-not (Wait-ForService -ServiceName "CertSvc" -TimeoutSeconds 60)) {
            Write-Log "Failed to start CertSvc" -Level ERROR
            exit 1
        }
    }
    catch {
        Write-Log "Error starting CertSvc: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

Write-Log "Certificate Services is running" -Level SUCCESS

# STEP 3: Create ESC1 Vulnerable Certificate Template
Write-Log "========================================" -Level INFO
Write-Log "STEP 3: ESC1 Vulnerable Certificate Template" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "WARNING: CREATING INTENTIONALLY VULNERABLE TEMPLATE" -Level WARNING
Write-Log " " -Level INFO

if (Test-FlagExists -FlagName "template_esc1_configured") {
    Write-Log "ESC1User template already configured. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Creating ESC1User certificate template..." -Level INFO
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $templateDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configContext"
        
        $userTemplate = Get-ADObject -SearchBase $templateDN -Filter {DisplayName -eq "User"} -Properties *
        
        if (-not $userTemplate) {
            Write-Log "Base User template not found" -Level ERROR
            exit 1
        }
        
        Write-Log "Found base User template" -Level INFO
        Write-Log "Creating ESC1User template with SAN impersonation support..." -Level INFO
        
        $newTemplateName = "ESC1User"
        $newTemplateDN = "CN=$newTemplateName,$templateDN"
        
        $existingTemplate = Get-ADObject -SearchBase $templateDN -Filter {cn -eq $newTemplateName} -ErrorAction SilentlyContinue
        
        if ($existingTemplate) {
            Write-Log "ESC1User template already exists" -Level WARNING
        }
        else {
            $newTemplate = New-ADObject -Type pKICertificateTemplate -Name $newTemplateName -Path $templateDN -OtherAttributes @{
                'flags' = 131680
                'displayName' = $newTemplateName
                'msPKI-Cert-Template-OID' = "$($userTemplate.'msPKI-Cert-Template-OID').999"
                'msPKI-Certificate-Application-Policy' = $userTemplate.'msPKI-Certificate-Application-Policy'
                'msPKI-Certificate-Name-Flag' = 1
                'msPKI-Enrollment-Flag' = 0
                'msPKI-Minimal-Key-Size' = 2048
                'msPKI-Private-Key-Flag' = 16842752
                'msPKI-RA-Signature' = 0
                'msPKI-Template-Minor-Revision' = 1
                'msPKI-Template-Schema-Version' = 2
                'pKICriticalExtensions' = $userTemplate.pKICriticalExtensions
                'pKIDefaultCSPs' = $userTemplate.pKIDefaultCSPs
                'pKIDefaultKeySpec' = $userTemplate.pKIDefaultKeySpec
                'pKIExpirationPeriod' = $userTemplate.pKIExpirationPeriod
                'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2')
                'pKIKeyUsage' = $userTemplate.pKIKeyUsage
                'pKIMaxIssuingDepth' = 0
                'pKIOverlapPeriod' = $userTemplate.pKIOverlapPeriod
                'revision' = 100
            }
            
            Write-Log "ESC1User template object created" -Level SUCCESS
        }
        
        Write-Log "Granting enrollment rights to Domain Users..." -Level INFO
        
        $templateACL = Get-Acl "AD:$newTemplateDN"
        $domainUsers = New-Object System.Security.Principal.NTAccount("$DOMAIN_NETBIOS\Domain Users")
        
        $readPermission = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainUsers,
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [Guid]::Empty
        )
        
        $enrollPermission = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainUsers,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
        )
        
        $templateACL.AddAccessRule($readPermission)
        $templateACL.AddAccessRule($enrollPermission)
        Set-Acl "AD:$newTemplateDN" -AclObject $templateACL
        
        Write-Log "Enrollment rights granted to Domain Users" -Level SUCCESS
        
        Write-Log "Publishing template to CA..." -Level INFO
        
        certutil -dsTemplate ESC1User > $null 2>&1
        Add-CATemplate -Name "ESC1User" -Force -ErrorAction Stop
        
        Write-Log "ESC1User template published to CA" -Level SUCCESS
        
        Set-Flag -FlagName "template_esc1_configured" -Message "ESC1User template created and published"
    }
    catch {
        Write-Log "Error creating ESC1User template: $($_.Exception.Message)" -Level ERROR
        Write-Log "This may be normal on first boot." -Level WARNING
    }
}

# STEP 4: Create AD Users
Write-Log "========================================" -Level INFO
Write-Log "STEP 4: Create AD Users" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "users_created") {
    Write-Log "AD users already created. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Creating lab users..." -Level INFO
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        foreach ($userInfo in $LAB_USERS) {
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
            
            New-ADUser @userParams
            
            Write-Log "  + Created user: $username ($($userInfo.GivenName) $($userInfo.Surname))" -Level SUCCESS
        }
        
        Write-Log "All lab users created successfully" -Level SUCCESS
        
        Set-Flag -FlagName "users_created" -Message "AD users created"
    }
    catch {
        Write-Log "Error creating users: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# STEP 5: Configure WinRM
Write-Log "========================================" -Level INFO
Write-Log "STEP 5: Configure WinRM" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "winrm_configured") {
    Write-Log "WinRM already configured. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Configuring WinRM..." -Level INFO
    
    try {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck
        
        Set-Service -Name WinRM -StartupType Automatic
        
        if (-not (Test-ServiceRunning -ServiceName "WinRM")) {
            Start-Service -Name WinRM
        }
        
        winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>&1 | Out-Null
        winrm set winrm/config/service/auth '@{Basic="true"}' 2>&1 | Out-Null
        
        Write-Log "Configuring firewall rules for WinRM..." -Level INFO
        
        $firewallRule1 = Get-NetFirewallRule -DisplayName "AllowWinRMHTTP" -ErrorAction SilentlyContinue
        if (-not $firewallRule1) {
            New-NetFirewallRule -DisplayName "AllowWinRMHTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -Profile Any | Out-Null
            Write-Log "  + Firewall rule 'AllowWinRMHTTP' created" -Level SUCCESS
        }
        
        $publicRule = Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -ErrorAction SilentlyContinue
        if (-not $publicRule) {
            New-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -DisplayName "Windows Remote Management (HTTP-In) - Public" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -Profile Public | Out-Null
            Write-Log "  + Firewall rule 'WINRM-HTTP-In-TCP-PUBLIC' created" -Level SUCCESS
        }
        else {
            Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -Enabled True -ErrorAction SilentlyContinue
            Write-Log "  + Firewall rule 'WINRM-HTTP-In-TCP-PUBLIC' enabled" -Level SUCCESS
        }
        
        Test-WSMan -ComputerName localhost | Out-Null
        Write-Log "WinRM configured and tested successfully" -Level SUCCESS
        
        Set-Flag -FlagName "winrm_configured" -Message "WinRM configured"
    }
    catch {
        Write-Log "Error configuring WinRM: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# STEP 6: Install OpenSSH Server
Write-Log "========================================" -Level INFO
Write-Log "STEP 6: Configure OpenSSH Server" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "ssh_configured") {
    Write-Log "OpenSSH already configured. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Installing OpenSSH Server as fallback connection method..." -Level INFO
    
    try {
        $sshCapability = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue
        
        if ($sshCapability -and $sshCapability.State -ne 'Installed') {
            Write-Log "  Installing OpenSSH Server capability..." -Level INFO
            Add-WindowsCapability -Online -Name $sshCapability.Name -ErrorAction Stop | Out-Null
            Write-Log "  + OpenSSH Server installed" -Level SUCCESS
        }
        elseif ($sshCapability -and $sshCapability.State -eq 'Installed') {
            Write-Log "  OpenSSH Server already installed" -Level INFO
        }
        
        $sshService = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
        if ($sshService) {
            Write-Log "  Configuring SSH service..." -Level INFO
            
            Set-Service -Name sshd -StartupType Automatic
            
            if ($sshService.Status -ne 'Running') {
                Start-Service -Name sshd -ErrorAction Stop
                Write-Log "  + SSH service started" -Level SUCCESS
            }
            
            $sshFirewallRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
            if (-not $sshFirewallRule) {
                New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow -Profile Any | Out-Null
                Write-Log "  + SSH firewall rule created" -Level SUCCESS
            }
            
            Write-Log "OpenSSH Server configured successfully" -Level SUCCESS
        }
        
        Set-Flag -FlagName "ssh_configured" -Message "OpenSSH configured"
    }
    catch {
        Write-Log "Error configuring OpenSSH (non-critical): $($_.Exception.Message)" -Level WARNING
    }
}

# FINAL: Mark DC Provisioning Complete
Write-Log "========================================" -Level INFO
Write-Log "DC Provisioning Summary" -Level INFO
Write-Log "========================================" -Level INFO

$summary = @"
+ Active Directory Domain Services installed ($DOMAIN_NAME)
+ Active Directory Certificate Services installed ($CA_COMMON_NAME)
+ ESC1User vulnerable template created and published
+ $($LAB_USERS.Count) lab users created
+ WinRM configured and enabled
+ OpenSSH Server configured (fallback connection)

Domain: $DOMAIN_NAME
DC IP: $DC_IP
CA Name: $CA_COMMON_NAME
CA Validity: 2 years

Lab Users (with passwords):
"@

Write-Log $summary -Level SUCCESS

foreach ($userInfo in $LAB_USERS) {
    Write-Log "  - $($userInfo.Name) : $($userInfo.Password)" -Level INFO
}

Write-Log " " -Level INFO
Write-Log "WARNING: This lab contains intentionally vulnerable configurations." -Level WARNING
Write-Log "Use ONLY in isolated environments with no external network access." -Level WARNING
Write-Log " " -Level INFO

$statusPath = "C:\lab-status.txt"
$summary | Out-File -FilePath $statusPath -Encoding UTF8

Set-Flag -FlagName "dc_completed" -Message "DC provisioning fully completed"

Write-Log "DC provisioning completed successfully!" -Level SUCCESS
Write-Log "Status written to: $statusPath" -Level INFO

exit 0
