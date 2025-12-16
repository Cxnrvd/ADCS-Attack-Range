#Requires -Version 5.1
<#
.SYNOPSIS
    Client workstation provisioning script for ADCS ESC1 Lab.

.DESCRIPTION
    Configures a Windows 10 VM as a domain-joined workstation for demonstrating
    ESC1-style AD CS certificate template abuse.

.NOTES
    Author: ADCS ESC1 Lab
    Compatible with: Windows PowerShell 5.1
    
    WARNING: FOR ISOLATED LAB ENVIRONMENTS ONLY!
    
.EXAMPLE
    .\client_provision.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Configuration variables
$DOMAIN_NAME = "adcs.local"
$DOMAIN_NETBIOS = "ADCS"
$DC_IP = "192.168.57.10"
$CLIENT_IP = "192.168.57.11"
$DOMAIN_ADMIN_USER = "Administrator"
$DOMAIN_ADMIN_PASSWORD = "LabAdmin@2024!Secure"

# Load helper functions
$helpersPath = "C:\provision\helpers.ps1"

if (-not (Test-Path $helpersPath)) {
    Write-Host "ERROR: Helper script not found at: $helpersPath" -ForegroundColor Red
    exit 1
}

. $helpersPath

Write-Log "========================================" -Level INFO
Write-Log "ADCS ESC1 Lab - CLIENT01 Provisioning Started" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Domain: $DOMAIN_NAME" -Level INFO
Write-Log "Client IP: $CLIENT_IP" -Level INFO
Write-Log "DC IP: $DC_IP" -Level INFO
Write-Log " " -Level INFO

# Check if already completed
if (Test-FlagExists -FlagName "client_completed") {
    Write-Log "CLIENT01 provisioning already completed. Skipping..." -Level SUCCESS
    Write-Log "To re-provision, delete: $(Get-FlagPath -FlagName 'client_completed')" -Level INFO
    exit 0
}

# STEP 1: Configure Network
Write-Log "========================================" -Level INFO
Write-Log "STEP 1: Configure Network" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "client_network_configured") {
    Write-Log "Network already configured. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Configuring static IP and DNS..." -Level INFO
    
    try {
        $adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -like '*Ethernet*'} | Select-Object -First 1
        
        if (-not $adapter) {
            Write-Log "No active network adapter found" -Level ERROR
            exit 1
        }
        
        Write-Log "  Using adapter: $($adapter.Name)" -Level INFO
        
        Remove-NetIPAddress -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        
        New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $CLIENT_IP -PrefixLength 24 -DefaultGateway "192.168.57.1" -ErrorAction Stop | Out-Null
        
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $DC_IP
        
        Write-Log "Network configured successfully" -Level SUCCESS
        Write-Log "  IP: $CLIENT_IP" -Level INFO
        Write-Log "  DNS: $DC_IP" -Level INFO
        
        Set-Flag -FlagName "client_network_configured" -Message "Network configured"
    }
    catch {
        Write-Log "Error configuring network: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# STEP 2: Configure Hosts File
Write-Log "========================================" -Level INFO
Write-Log "STEP 2: Configure Hosts File" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "client_hosts_configured") {
    Write-Log "Hosts file already configured. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Adding hosts file entries..." -Level INFO
    
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsEntries = @(
            "$DC_IP    dc.adcs.local dc"
            "$DC_IP    adcs.local"
        )
        
        $currentHosts = Get-Content $hostsPath -ErrorAction SilentlyContinue
        
        foreach ($entry in $hostsEntries) {
            if ($currentHosts -notcontains $entry) {
                Add-Content -Path $hostsPath -Value $entry
                Write-Log "  + Added: $entry" -Level SUCCESS
            }
        }
        
        Write-Log "Hosts file configured" -Level SUCCESS
        
        Set-Flag -FlagName "client_hosts_configured" -Message "Hosts file configured"
    }
    catch {
        Write-Log "Error configuring hosts file: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# STEP 3: Test DNS Resolution
Write-Log "========================================" -Level INFO
Write-Log "STEP 3: Test DNS Resolution" -Level INFO
Write-Log "========================================" -Level INFO

Write-Log "Testing DNS resolution with retry logic..." -Level INFO

$dnsResolved = $false
for ($retryCount = 1; $retryCount -le 3; $retryCount++) {
    if (Test-DNSResolution -Hostname "dc.adcs.local" -DNSServer $DC_IP) {
        Write-Log "DNS resolution successful" -Level SUCCESS
        $dnsResolved = $true
        break
    }
    else {
        Write-Log "  Attempt $retryCount/3: DNS resolution failed" -Level WARNING
        
        if ($retryCount -lt 3) {
            Write-Log "  Flushing DNS cache and retrying..." -Level INFO
            ipconfig /flushdns | Out-Null
            ipconfig /registerdns | Out-Null
            Start-Sleep -Seconds 5
        }
    }
}

if (-not $dnsResolved) {
    Write-Log "DNS resolution failed after retries (will rely on hosts file)" -Level WARNING
}

# STEP 4: Join Domain
Write-Log "========================================" -Level INFO
Write-Log "STEP 4: Join Domain" -Level INFO
Write-Log "========================================" -Level INFO

# Check if we're in domain already
$currentlyJoined = Test-DomainJoined -ExpectedDomain $DOMAIN_NAME

if ($currentlyJoined) {
    Write-Log "Already joined to domain $DOMAIN_NAME" -Level SUCCESS
    
    if (Test-FlagExists -FlagName "client_domain_joined") {
        Write-Log "Domain join previously completed" -Level SUCCESS
    }
    else {
        Set-Flag -FlagName "client_domain_joined" -Message "Domain join completed"
    }
}
else {
    if (Test-FlagExists -FlagName "client_domain_joined") {
        Write-Log "Domain join flag exists but not actually joined - removing flag" -Level WARNING
        Remove-Flag -FlagName "client_domain_joined"
    }
}

if (-not (Test-FlagExists -FlagName "client_domain_joined")) {
    Write-Log "Joining domain '$DOMAIN_NAME'..." -Level INFO
    
    try {
        Write-Log "Waiting for DC to be fully ready..." -Level INFO
        Start-Sleep -Seconds 15
        
        $dcReachable = $false
        $maxDomainAttempts = 8
        
        for ($i = 1; $i -le $maxDomainAttempts; $i++) {
            Write-Log "  Domain reachability check $i/$maxDomainAttempts..." -Level INFO
            
            $pingSuccess = Test-NetworkConnectivity -TargetHost $DC_IP -Count 2
            $dnsSuccess = Test-DNSResolution -Hostname "dc.adcs.local" -DNSServer $DC_IP
            
            if ($pingSuccess -and $dnsSuccess) {
                try {
                    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DOMAIN_NAME)))
                    if ($domain) {
                        $dcReachable = $true
                        Write-Log "  + Domain '$DOMAIN_NAME' is reachable and responsive" -Level SUCCESS
                        break
                    }
                }
                catch {
                    Write-Log "  Domain query failed: $($_.Exception.Message)" -Level WARNING
                }
            }
            
            if ($i -lt $maxDomainAttempts) {
                Write-Log "  DC not fully ready, waiting 15 seconds..." -Level WARNING
                Start-Sleep -Seconds 15
            }
        }
        
        if (-not $dcReachable) {
            Write-Log "CRITICAL: Domain '$DOMAIN_NAME' is not reachable after $maxDomainAttempts attempts" -Level ERROR
            Write-Log "  Ensure:" -Level ERROR
            Write-Log "  1. DC VM is running: vagrant status" -Level ERROR
            Write-Log "  2. DC has completed AD DS provisioning" -Level ERROR
            Write-Log "  3. Network connectivity is working" -Level ERROR
            Write-Log "  4. DNS is configured correctly" -Level ERROR
            exit 1
        }
        
        Write-Log "Creating domain credentials for join..." -Level INFO
        $domainCred = New-Object System.Management.Automation.PSCredential(
            "$DOMAIN_NETBIOS\$DOMAIN_ADMIN_USER",
            (ConvertTo-SecureString $DOMAIN_ADMIN_PASSWORD -AsPlainText -Force)
        )
        
        Write-Log "  Joining domain as $DOMAIN_NETBIOS\$DOMAIN_ADMIN_USER..." -Level INFO
        Write-Log "  Domain: $DOMAIN_NAME" -Level INFO
        Write-Log "  DC: $DC_IP" -Level INFO
        
        try {
            Add-Computer -DomainName $DOMAIN_NAME -Credential $domainCred -Force -ErrorAction Stop
            
            Write-Log "Domain join initiated successfully" -Level SUCCESS
            Write-Log "System will reboot to complete domain join..." -Level INFO
            
            Set-Flag -FlagName "client_domain_joined" -Message "Domain join initiated, reboot pending"
            
            Restart-Computer -Force
        }
        catch {
            Write-Log "Domain join failed: $($_.Exception.Message)" -Level ERROR
            
            $errorMsg = $_.Exception.Message.ToLower()
            
            if ($errorMsg -like "*credentials*" -or $errorMsg -like "*password*" -or $errorMsg -like "*logon failure*") {
                Write-Log " " -Level ERROR
                Write-Log "CREDENTIAL ERROR DETECTED:" -Level ERROR
                Write-Log "  The domain credentials appear to be incorrect" -Level ERROR
                Write-Log "  Username: $DOMAIN_NETBIOS\$DOMAIN_ADMIN_USER" -Level ERROR
                Write-Log "  Ensure DC provisioning completed successfully" -Level ERROR
            }
            elseif ($errorMsg -like "*network*" -or $errorMsg -like "*rpc*") {
                Write-Log " " -Level ERROR
                Write-Log "NETWORK ERROR DETECTED:" -Level ERROR
                Write-Log "  Cannot communicate with domain controller" -Level ERROR
                Write-Log "  Check network connectivity to $DC_IP" -Level ERROR
            }
            elseif ($errorMsg -like "*domain*" -or $errorMsg -like "*not found*") {
                Write-Log " " -Level ERROR
                Write-Log "DOMAIN NOT FOUND ERROR:" -Level ERROR
                Write-Log "  Domain '$DOMAIN_NAME' cannot be located" -Level ERROR
                Write-Log "  Verify DC has completed AD DS installation" -Level ERROR
            }
            
            Write-Log " " -Level ERROR
            exit 1
        }
    }
    catch {
        Write-Log "Error during domain join preparation: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# Verify domain join (after reboot)
if (-not (Test-DomainJoined -ExpectedDomain $DOMAIN_NAME)) {
    Write-Log "Domain join verification failed" -Level ERROR
    exit 1
}

Write-Log "Domain join verified successfully" -Level SUCCESS

# Verify secure channel
if (Test-DomainSecureChannel) {
    Write-Log "Secure channel to domain controller is healthy" -Level SUCCESS
}
else {
    Write-Log "WARNING: Secure channel test failed (may be temporary)" -Level WARNING
}

# STEP 5: Verify Certificate Tools
Write-Log "========================================" -Level INFO
Write-Log "STEP 5: Verify Certificate Tools" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "client_cert_tools_verified") {
    Write-Log "Certificate tools already verified. Skipping..." -Level SUCCESS
}
else {
    Write-Log "Verifying certificate tools..." -Level INFO
    
    try {
        $certutilVersion = certutil.exe -? 2>&1 | Select-Object -First 1
        
        if ($certutilVersion) {
            Write-Log "  + certutil.exe is available" -Level SUCCESS
        }
        else {
            Write-Log "  certutil.exe not found" -Level WARNING
        }
        
        Set-Flag -FlagName "client_cert_tools_verified" -Message "Certificate tools verified"
    }
    catch {
        Write-Log "Error verifying certificate tools: $($_.Exception.Message)" -Level WARNING
    }
}

# STEP 6: Configure WinRM
Write-Log "========================================" -Level INFO
Write-Log "STEP 6: Configure WinRM" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "client_winrm_configured") {
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
        
        Test-WSMan -ComputerName localhost | Out-Null
        Write-Log "WinRM configured and tested successfully" -Level SUCCESS
        
        Set-Flag -FlagName "client_winrm_configured" -Message "WinRM configured"
    }
    catch {
        Write-Log "Error configuring WinRM: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# STEP 7: Install OpenSSH Server
Write-Log "========================================" -Level INFO
Write-Log "STEP 7: Configure OpenSSH Server" -Level INFO
Write-Log "========================================" -Level INFO

if (Test-FlagExists -FlagName "client_ssh_configured") {
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
        }
        
        Set-Flag -FlagName "client_ssh_configured" -Message "OpenSSH configured"
    }
    catch {
        Write-Log "Error configuring OpenSSH (non-critical): $($_.Exception.Message)" -Level WARNING
    }
}

# FINAL: Mark CLIENT01 Provisioning Complete
Write-Log "========================================" -Level INFO
Write-Log "CLIENT01 Provisioning Summary" -Level INFO
Write-Log "========================================" -Level INFO

$summary = @"
+ Network configured with static IP ($CLIENT_IP)
+ DNS configured to use DC ($DC_IP)
+ Hosts file entries added
+ Joined to domain ($DOMAIN_NAME)
+ Certificate tools verified (certutil)
+ WinRM configured and enabled
+ OpenSSH Server configured (fallback connection)

Client IP: $CLIENT_IP
Domain: $DOMAIN_NAME
DC IP: $DC_IP
"@

Write-Log $summary -Level SUCCESS

Set-Flag -FlagName "client_completed" -Message "CLIENT01 provisioning fully completed"

Write-Log "CLIENT01 provisioning completed successfully!" -Level SUCCESS

exit 0
