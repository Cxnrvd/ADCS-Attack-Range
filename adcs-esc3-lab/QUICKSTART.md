# ADCS ESC3 Lab - Quick Start Guide

## 🚀 90-Second Setup

### 1. Start Domain Controller
```powershell
cd E:\ADCS\adcs-esc3-lab
vagrant up dc
# Wait ~15 mins for AD DS installation and automatic reboot
vagrant reload dc --provision
```

### 2. Manually Install CA
1. Get RDP port: `vagrant port dc`
2. Connect: `mstsc /v:127.0.0.1:2200`
3. Login: `Administrator` / `P@ssw0rd!123`
4. Server Manager → Add Roles → **AD CS**
5. Install **Enterprise Root CA** named `ADCS-CA-ESC3`

### 3. Create ESC3 Templates

#### Template 1: ESC3-Agent (Enrollment Agent)
- Open `certsrv.msc`
- Duplicate **User** template
- Name: `ESC3-Agent`
- Extensions → Application Policies: **Certificate Request Agent** (ONLY)
- Security: **Authenticated Users** = Read + Enroll
- Publish to CA

#### Template 2: ESC3-User (Vulnerable)
- Duplicate **User** template
- Name: `ESC3-User`
- Issuance Requirements:
  - ✅ **This number of authorized signatures: 1**
  - Policy: **Certificate Request Agent**
  - ✅ **Valid existing certificate**
- Extensions: Verify **Client Authentication** EKU present
- Security: **Authenticated Users** = Read + Enroll
- Publish to CA

### 4. Start Client
```powershell
vagrant up client
# Auto-joins domain - wait ~15 mins
```

### 5. Verify
```powershell
vagrant status
vagrant powershell dc -c "certutil -CATemplates | Select-String ESC3"
vagrant powershell client -c "Get-ComputerInfo | Select CsDomain"
```

## 🎯 Attack Flow

1. **Enroll for Enrollment Agent** (ESC3-Agent template)
2. **Request certificate on behalf of Administrator** (ESC3-User template)
3. **Use Admin certificate** for authentication

See full attack walkthrough in README.md!

## 📝 Key Configuration

| Component | Value |
|-----------|-------|
| Domain | adcs.local |
| DC IP | 192.168.57.20 |
| Client IP | 192.168.57.21 |
| Admin Password | P@ssw0rd!123 |
| CA Name | ADCS-CA-ESC3 |

## 🔧 Troubleshooting

**Client won't join domain?**
```powershell
vagrant powershell client -c "Resolve-DnsName adcs.local"
# Manual join if needed:
vagrant powershell client -c @"
`$pass = ConvertTo-SecureString 'P@ssw0rd!123' -AsPlainText -Force
`$cred = New-Object PSCredential('ADCS\Administrator', `$pass)
Add-Computer -DomainName adcs.local -Credential `$cred -Force -Restart
"@
```

**Primary Domain Controller error?**
- Remove `-Server` parameter from `Add-Computer`
- Let DNS auto-discovery find the DC

---

✅ **Ready to demonstrate ESC3!**
