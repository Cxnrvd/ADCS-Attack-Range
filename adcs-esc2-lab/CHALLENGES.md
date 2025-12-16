# ESC2 Lab Deployment Challenges & Solutions

## Summary of Challenges

### Challenge #1: Incorrect Vagrant Box Names
**Issue:** `mayfly/windows-server-2019` was used instead of `mayfly/windows_server2019`.
**Fix:** Corrected Vagrantfile box names.

### Challenge #2: Boot Timeouts
**Issue:** Windows Server 2019 takes a long time to boot/sysprep.
**Fix:** Increased `config.vm.boot_timeout` to 2400 seconds (40 mins).

### Challenge #3: VirtualBox Directory Conflicts
**Issue:** "Machine already exists" errors due to lingering directories in `E:\Virtual Machines`.
**Fix:** 
1. Used unique VM names (`ESC2-DC` vs `ADCS-ESC2-DC`).
2. Manually deleted conflicting directories before deployment.

### Challenge #4: Missing Configuration Files
**Issue:** Vagrantfile and documentation missing from directory.
**Fix:** Re-created files with correct configuration.

### Challenge #5: Persistent Vagrant Locks
**Issue:** "Another process is using this machine".
**Fix:** Force-killed ruby/vagrant/VBoxHeadless processes.

### Challenge #6: WinRM Connectivity Failure (CRITICAL)
**Issue:** `mayfly/windows_server2019` box starts but WinRM service is unreachable (timeout).
**Diagnosis:** Box configuration issues or network driver incompatibility (virtio) in this specific environment.
**Solution:** Reverted to **StefanScherer/windows_2019** box with ESC1-proven configuration (no virtio adapters). This configuration worked in the previous lab.

---
## Current Status
- **DC Deployment:** In Progress
- **Configuration:** StefanScherer/windows_2019 (ESC1 Config)
- **Networking:** Host-only (192.168.57.x) + NAT
