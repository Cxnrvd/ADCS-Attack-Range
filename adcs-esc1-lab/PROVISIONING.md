# ADCS ESC1 Lab - Manual Provisioning Guide

This guide covers the manual steps required to complete lab setup.

---

## Overview

The lab requires **2 manual steps** due to Windows Server automation limitations:

1. **CA Installation** (Method 1 or Method 2)
2. **ESC1User Template Creation** (Method 1 or Method 2)

**Total Time:** ~5-10 minutes

---

## Step 1: Install CA (Choose One Method)

### Method 1: PowerShell (Fastest - 2 minutes)

After `vagrant reload dc --provision` completes:

```powershell
vagrant powershell dc -c "Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'ADCS-CA' -Force"
```

**Expected Output:**
```
CA Name: ADCS-CA
CA Type: Enterprise Root CA
Configuration succeeded
```

### Method 2: Server Manager GUI (5 minutes)

1. **Connect via RDP:**
   ```powershell
   # Get RDP port
   vagrant port dc
   # Connect to localhost:<port> (usually 2204)
   # Credentials: ADCS\Administrator / LabAdmin@2024!Secure
   ```

2. **Open Server Manager** (opens automatically or run `servermanager.msc`)

3. **Configure AD CS:**
   - Click yellow warning flag (top-right)
   - Click "Configure Active Directory Certificate Services"
   - Next → Check "Certification Authority" → Next

4. **Setup Type:** Enterprise CA → Next

5. **CA Type:** Root CA → Next

6. **Private Key:** Create a new private key → Next

7. **Cryptography:**
   - Provider: RSA#Microsoft Software Key Storage Provider
   - Key Length: 2048
   - Hash: SHA256
   - Next

8. **CA Name:** ADCS-CA → Next

9. **Validity:** 5 Years → Next

10. **Database:** Use defaults → Next

11. **Confirm** → Configure → Close

**Verify CA is running:**
```powershell
vagrant powershell dc -c "Get-Service CertSvc"
# Expected: Running
```

---

## Step 2: Create ESC1User Template (Choose One Method)

### Method 1: PowerShell (Fastest - 2 minutes)

```powershell
vagrant powershell dc -c @"
Import-Module ActiveDirectory
`$config = ([ADSI]'LDAP://RootDSE').configurationNamingContext
`$templateDN = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,' + `$config
`$userTemplate = Get-ADObject -SearchBase `$templateDN -Filter {DisplayName -eq 'User'} -Properties *

New-ADObject -Type pKICertificateTemplate -Name 'ESC1User' -Path `$templateDN -OtherAttributes @{
    'flags' = 131680
    'displayName' = 'ESC1User'
    'msPKI-Cert-Template-OID' = \"`$(`$userTemplate.'msPKI-Cert-Template-OID').999\"
    'msPKI-Certificate-Application-Policy' = `$userTemplate.'msPKI-Certificate-Application-Policy'
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'msPKI-Minimal-Key-Size' = 2048
    'msPKI-Private-Key-Flag' = 16842752
    'msPKI-Template-Schema-Version' = 2
    'pKIDefaultKeySpec' = `$userTemplate.pKIDefaultKeySpec
    'pKIExpirationPeriod' = `$userTemplate.pKIExpirationPeriod
    'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2')
    'pKIKeyUsage' = `$userTemplate.pKIKeyUsage
    'pKIMaxIssuingDepth' = 0
    'pKIOverlapPeriod' = `$userTemplate.pKIOverlapPeriod
    'revision' = 100
}

`$templateACL = Get-Acl 'AD:CN=ESC1User,CN=Certificate Templates,CN=Public Key Services,CN=Services,' + `$config
`$domainUsers = New-Object System.Security.Principal.NTAccount('ADCS\Domain Users')
`$enrollPermission = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(`$domainUsers, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AccessControlType]::Allow, [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55')
`$templateACL.AddAccessRule(`$enrollPermission)
Set-Acl ('AD:CN=ESC1User,CN=Certificate Templates,CN=Public Key Services,CN=Services,' + `$config) -AclObject `$templateACL

certutil -dsTemplate ESC1User
Add-CATemplate -Name 'ESC1User' -Force
Write-Host 'ESC1User template created and published!' -ForegroundColor Green
"@
```

### Method 2: GUI (10 minutes) - Detailed Walkthrough

#### Part A: Duplicate User Template

1. **Open Certificate Templates Console:**
   ```
   Start → Run → certtmpl.msc
   ```

2. **Find User template:**
   - Scroll down to "User" template
   - Right-click → Duplicate Template

3. **Compatibility Tab:**
   - Certification Authority: Windows Server 2012 R2
   - Certificate recipient: Windows 8.1 / Windows Server 2012 R2
   - Click OK on warnings

4. **General Tab:**
   - Template name: `ESC1User`
   - Template display name: `ESC1User`
   - Validity period: 1 year
   - ☑ Publish certificate in Active Directory

5. **Request Handling Tab:**
   - Purpose: Signature and encryption
   - ☐ Do not allow private key to be exported (UNCHECK)
   - Minimum key size: 2048

6. **Subject Name Tab (CRITICAL - This creates the vulnerability!):**
   - ☑ **Supply in the request** (This is the ESC1 vulnerability!)
   - When prompted "This template may issue certificates..." → Click YES

7. **Security Tab:**
   - Click Add → Enter "Domain Users" → Check Names → OK
   - Select "Domain Users"
   - Permissions for Domain Users:
     - ☑ Read (Allow)
     - ☑ Enroll (Allow)
   - Click OK

8. **Extensions Tab:**
   - Select "Application Policies" → Edit
   - Verify these exist:
     - Client Authentication (1.3.6.1.5.5.7.3.2)
     - Secure Email (1.3.6.1.5.5.7.3.4)
   - Click OK

9. **Click OK** to create the template

#### Part B: Publish Template to CA

1. **Open Certification Authority Console:**
   ```
   Start → Run → certsrv.msc
   ```

2. **Publish Template:**
   - Expand "ADCS-CA"
   - Right-click "Certificate Templates" → New → Certificate Template to Issue

3. **Select ESC1User:**
   - Find "ESC1User" in the list
   - Click OK

4. **Verify:**
   - "ESC1User" should now appear in Certificate Templates list

**Verify template is available:**
```powershell
vagrant powershell dc -c "certutil -CATemplates | Select-String ESC1User"
# Should see: ESC1User
```

---

## Step 3: Provision CLIENT01

After CA and template are configured:

```powershell
vagrant up client01
```

**What happens:**
- Creates Windows 10 VM
- Joins adcs.local domain
- Configures network (192.168.57.11)
- Time: ~10-15 minutes

---

## Verification

```powershell
# 1. Check VMs
vagrant status

# 2. Verify CA
vagrant powershell dc -c "certutil -ping"

# 3. Verify template
vagrant powershell dc -c "certutil -CATemplates | Select-String ESC1"

# 4. Verify users
vagrant powershell dc -c "Get-ADUser -Filter {SamAccountName -like '*john*' -or SamAccountName -like '*jane*'} | Select Name"

# 5. Verify CLIENT01 domain join
vagrant powershell client01 -c "Get-ComputerInfo | Select CsDomain"
```

**All checks passing?** Lab is ready! → See [README.md](README.md) for ESC1 attack demonstration.

---

## Troubleshooting

### CA Service Won't Start

```powershell
vagrant powershell dc -c "icacls C:\Windows\System32\CertLog /grant 'NETWORK SERVICE:(OI)(CI)F' /T; Restart-Service CertSvc"
```

### Template Not Visible

```powershell
vagrant powershell dc -c "Restart-Service CertSvc; Start-Sleep 5; certutil -CATemplates"
```

### Cannot RDP to DC

```powershell
vagrant port dc  # Note the RDP port
mstsc /v:localhost:<port>
```

---

## Lab Credentials

**Domain Admin:**
- Username: `ADCS\Administrator`
- Password: `LabAdmin@2024!Secure`

**Lab Users:**
| Username | Password |
|----------|----------|
| johndoe | P@ssw0rd!John2024 |
| janesmith | P@ssw0rd!Jane2024 |
| alicejohnson | P@ssw0rd!Alice2024 |
| bobwilliams | P@ssw0rd!Bob2024 |
| charliebrown | P@ssw0rd!Charlie2024 |

---

## Complete Workflow Summary

```powershell
# 1. Initial DC setup
vagrant up dc
vagrant reload dc --provision

# 2. Manual CA installation (choose method)
vagrant powershell dc -c "Install-AdcsCertificationAuthority..."
# OR use Server Manager GUI

# 3. Manual ESC1User template (choose method)
vagrant powershell dc -c @"...[PowerShell script]..."@
# OR use certtmpl.msc GUI

# 4. Provision client
vagrant up client01

# Done! Total time: 30-40 minutes
```
