# Manual AD CS & ESC2 Template Setup Guide

## Purpose
This guide covers the manual steps to install the **Certificate Authority (CA)** and create the vulnerable **ESC2User** template. Use this guide if the automated provisioning script encounters the `0x80072082` error.

---

## Part 1: Install Active Directory Certificate Services (CA)

1.  **Log in to the DC**:
    - Open VirtualBox Console for `ADCS-ESC2-DC` (or `ESC2-DC`).
    - Login as **Administrator**.
    - Password: `P@ssw0rd!123`

2.  **Open Server Manager**:
    - Click **Manage** > **Add Roles and Features**.
    - Click **Next** until you reach **Server Roles**.
    - Ensure **Active Directory Certificate Services** is checked.
    - Click **Next** > **Next** > **Next** > **Install**.
    - Wait for installation to complete.

3.  **Configure AD CS**:
    - In Server Manager, click the **Yellow Warning Flag** (top right).
    - Click **"Configure Active Directory Certificate Services on the destination server"**.
    - **Credentials**: Keep default (ADCS\Administrator) > **Next**.
    - **Role Services**: Check **Certification Authority** > **Next**.
    - **Setup Type**: Select **Enterprise CA** > **Next**.
    - **CA Type**: Select **Root CA** > **Next**.
    - **Private Key**: Select **Create a new private key** > **Next**.
    - **Cryptography**:
        - Provider: **RSA#Microsoft Software Key Storage Provider** (or default).
        - Key Length: **2048**.
        - Hash: **SHA256**.
        - Click **Next**.
    - **CA Name**:
        - Common Name: `ADCS-CA-ESC2` (or `Manual-CA` if that fails).
        - Click **Next**.
    - **Validity**: 5 Years > **Next**.
    - **Database**: Default paths > **Next**.
    - **Confirmation**: Click **Configure**.

4.  **Verify**:
    - Open command prompt and run: `certutil -ping`
    - It should confirm the CA is creating.

---

## Part 2: Create Vulnerable ESC2 Template

1.  **Open Certificate Templates Console**:
    - Press `Win+R`, type `certtmpl.msc`, and press Enter.

2.  **Duplicate User Template**:
    - Find the **User** template in the list.
    - Right-click **User** > **Duplicate Template**.

3.  **Configure General Tab**:
    - Template display name: **ESC2User**
    - Validity period: **1 years**
    - **Uncheck** "Publish certificate in Active Directory".

4.  **Configure Request Handling Tab**:
    - **Uncheck** "Archive subject's encryption private key".
    - **Purpose**: Signature and encryption.

5.  **Configure Subject Name Tab (CRITICAL FOR ESC2)**:
    - Select **Supply in the request**.
    - Click **OK** on the warning popup.

6.  **Configure Extensions Tab (CRITICAL FOR ESC2)**:
    - Select **Application Policies** and click **Edit**.
    - **Remove** all policies (Client Auth, Email Protection, etc.) so the list is **empty**.
    - Click **OK**.
    - *Note: This creates the "Any Purpose" (no EKU) vulnerability.*

7.  **Configure Security Tab**:
    - Click **Add...** > Type `Authenticated Users` > Check Names > OK.
    - Select **Authenticated Users**.
    - Check **Allow** for **Enroll**.
    - Ensure **Read** is also allowed.

8.  **Save Template**:
    - Click **OK** to save the new template.

---

## Part 3: Publish the Template

1.  **Open Certification Authority Console**:
    - Press `Win+R`, type `certsrv.msc`, and press Enter.

2.  **Publish ESC2User**:
    - Expand your CA name (e.g., `ADCS-CA-ESC2`).
    - Right-click **Certificate Templates** folder.
    - Select **New** > **Certificate Template to Issue**.
    - Select **ESC2User** from the list.
    - Click **OK**.

3.  **Verify**:
    - You should see `ESC2User` in the list of Certificate Templates in the CA console.


