# ADCS ESC4 Lab - Vulnerable Template Access Control

> **⚠️ WARNING**: This is an intentionally vulnerable lab environment for educational purposes only. Do NOT deploy in production!

## Overview

Fully automated Active Directory Certificate Services lab demonstrating **ESC4 vulnerability** - weak Access Control List (ACL) on certificate templates allows an attacker to modify template configuration (e.g., enable vulnerable EKUs or enrollment settings) to escalate privileges.

## Lab Architecture

- **Domain**: `adcs.local`
- **Network**: Host-Only `192.168.57.0/24`
- **DC**: `192.168.57.22` (Windows Server 2019)
- **Client**: `192.168.57.23` (Windows 10)

## Provisioning Walkthrough

### 1. Prerequisites
- VirtualBox 7.x
- Vagrant 2.3+

### 2. Start the Domain Controller
This sets up AD DS. CA installation is manual.

```powershell
cd E:\ADCS\adcs-esc4-lab
vagrant up dc
# (Wait for reboot - Vagrant will handle it or you may need to 'vagrant reload dc --provision')
```

### 3. Manual Certificate Authority Installation
1. RDP to DC (`192.168.57.22` or `vagrant port dc`). Login: `Administrator` / `P@ssw0rd!123`/ Michael123!.
2. **Install AD CS** via Server Manager (Role: Certification Authority).
3. **Configure AD CS**: Enterprise CA, Root CA, RSA#2048, Name: `ADCS-CA-ESC4`.

### 4. Configure ESC4 Vulnerable Template
1. Open `certsrv.msc` -> Right-click **Certificate Templates** -> **Manage**.
2. Duplicate **User** template -> Name: `ESC4` -> Validity: 1 year.
3. **Security Tab (THE VULNERABILITY)**:
   - Add **Authenticated Users**.
   - **Important**: Grant "Full Control" or specifically **Write** permissions (Write Owner, Write DACL, Write Property).
   - This allows any user to modify the template configuration later.
4. Publish the `ESC4` template in the CA.

### 5. Start Client
```powershell
vagrant up client
```
(Manual hostname and Domain Join will happen automatically).

## Lab Credentials

| Username | Password | Email |
|----------|----------|-------|
| `ADCS\johndoe` | `Summer2024!` | johndoe@adcs.local |
| `ADCS\janesmith` | `Winter2024!` | janesmith@adcs.local |
| `ADCS\alicejohnson` | `Spring2024!` | alicejohnson@adcs.local |
| `ADCS\bobwilliams` | `Autumn2024!` | bobwilliams@adcs.local |
| `ADCS\charliebrown` | `Coffee2024!` | charliebrown@adcs.local |
| `ADCS\Administrator` | `P@ssw0rd!123` | - |

## ESC4 Attack Walkthrough

1. **Discovery**: Use `Certify.exe find` to identify templates where you have Write access.
2. **Exploitation**:
   - Use `Certify.exe` or `BloodyAD` to **modify** the `ESC4` template.
   - **Disable** "Manager Approval".
   - **Enable** "Client Authentication" EKU.
   - **Enable** "Enrollee Supplies Subject" (SAN).
3. **Escalation**:
   - Request a certificate as Administrator (using the modified template):
     `.\Certify.exe request /ca:192.168.57.22\ADCS-CA-ESC4 /template:ESC4 /altname:Administrator`
   - Use the certificate to authenticate (PKINIT) via Rubeus.
4. **Cleanup**: Restore the template configuration.

## Verification Checklist

```powershell
# Verify DC
vagrant powershell dc -c "Get-Service NTDS, CertSvc"

# Verify Client
vagrant powershell client -c "Get-ComputerInfo | Select CsDomain, CsName"
```
