#Requires -Version 5.1

# Helper functions for ADCS ESC1 Lab provisioning
# Compatible with Windows PowerShell 5.1
# Uses ONLY ASCII characters - no UTF-8

[CmdletBinding()]
param()

# Base path for state flags and logs (works inside VM)
$script:STATE_PATH = "C:\lab-state"
$script:LOG_PATH = "C:\lab-logs"

# Ensure directories exist
function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

Ensure-Directory -Path $script:STATE_PATH
Ensure-Directory -Path $script:LOG_PATH

# Logging function with color-coded output
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        'INFO'    { Write-Host $logMessage -ForegroundColor Cyan }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
    }
    
    # File output
    $logFile = Join-Path $script:LOG_PATH "provision_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

# Idempotency flag functions
function Get-FlagPath {
    param([string]$FlagName)
    return Join-Path $script:STATE_PATH "$FlagName.flag"
}

function Test-FlagExists {
    param([string]$FlagName)
    return Test-Path (Get-FlagPath -FlagName $FlagName)
}

function Set-Flag {
    param(
        [string]$FlagName,
        [string]$Message = ""
    )
    $flagPath = Get-FlagPath -FlagName $FlagName
    $content = @{
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Message = $Message
    } | ConvertTo-Json
    Set-Content -Path $flagPath -Value $content
}

function Remove-Flag {
    param([string]$FlagName)
    $flagPath = Get-FlagPath -FlagName $FlagName
    if (Test-Path $flagPath) {
        Remove-Item $flagPath -Force
    }
}

# Service management functions
function Test-ServiceRunning {
    param([string]$ServiceName)
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return ($service.Status -eq 'Running')
    }
    catch {
        return $false
    }
}

function Wait-ForService {
    param(
        [string]$ServiceName,
        [int]$TimeoutSeconds = 60
    )
    
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (Test-ServiceRunning -ServiceName $ServiceName) {
            return $true
        }
        Start-Sleep -Seconds 5
        $elapsed += 5
    }
    return $false
}

function Start-ServiceIfNotRunning {
    param([string]$ServiceName)
    if (-not (Test-ServiceRunning -ServiceName $ServiceName)) {
        Start-Service -Name $ServiceName -ErrorAction Stop
        return Wait-ForService -ServiceName $ServiceName
    }
    return $true
}

# AD verification functions
function Test-ADDSInstalled {
    try {
        $service = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
        return ($null -ne $service -and $service.Status -eq 'Running')
    }
    catch {
        return $false
    }
}

function Test-DomainJoined {
    param([string]$ExpectedDomain = $null)
    
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $isDomainJoined = $computerSystem.PartOfDomain
        
        if ($ExpectedDomain) {
            return ($isDomainJoined -and $computerSystem.Domain -eq $ExpectedDomain)
        }
        return $isDomainJoined
    }
    catch {
        return $false
    }
}

function Test-DomainSecureChannel {
    try {
        Test-ComputerSecureChannel -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# DNS functions
function Test-DNSResolution {
    param(
        [string]$Hostname,
        [string]$DNSServer = $null
    )
    
    try {
        if ($DNSServer) {
            $result = Resolve-DnsName -Name $Hostname -Server $DNSServer -ErrorAction Stop
        }
        else {
            $result = Resolve-DnsName -Name $Hostname -ErrorAction Stop
        }
        return ($null -ne $result)
    }
    catch {
        return $false
    }
}

# Network functions
function Test-NetworkConnectivity {
    param(
        [string]$TargetHost,
        [int]$Count = 2
    )
    
    try {
        $result = Test-Connection -ComputerName $TargetHost -Count $Count -Quiet
        return $result
    }
    catch {
        return $false
    }
}

# Certificate Services functions
function Test-CertificateServicesInstalled {
    try {
        $service = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
        return ($null -ne $service)
    }
    catch {
        return $false
    }
}
