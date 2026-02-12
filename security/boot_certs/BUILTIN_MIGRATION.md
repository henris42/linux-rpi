# Boot Certificates: Built-in Kernel Code

## Overview

The boot certificate validation system has been converted from a loadable module to **built-in kernel code**. This is a critical security requirement: boot certificate validation must occur before any third-party modules are loaded.

## Why Built-in?

### Security Requirements

1. **Early Validation**: Certificate chain must be validated before module loading begins
2. **Tamper Resistance**: Cannot be prevented from loading by malicious code
3. **Trust Anchor**: Provides root of trust for all subsequent module signature verification
4. **Dependency Order**: Third-party modules depend on certificate validation being complete

### Technical Requirements

1. **Timing**: Must run after filesystem initialization but before module loading
2. **Boot Partition**: Requires /boot/firmware to be mounted (handled by initramfs)
3. **Keyring Setup**: Must populate and seal keyrings before any module can request verification

## What Changed

### Code Changes

| Component | Old (Module) | New (Built-in) |
|-----------|--------------|----------------|
| **Kconfig** | `tristate "..."` | `bool "..."` |
| **Init** | `module_init()` | `late_initcall()` |
| **Exit** | `module_exit()` | Kept but unused |
| **Includes** | `#include <linux/module.h>` | Removed (already have init.h) |
| **Metadata** | `MODULE_LICENSE()`, etc. | Removed |

### Build Changes

- **Before**: `CONFIG_BOOT_CERTS_SYSFS=m` → builds `boot_certs_sysfs.ko`
- **After**: `CONFIG_BOOT_CERTS_SYSFS=y` → built into `vmlinux`

### Runtime Changes

- **Before**: `sudo insmod boot_certs_sysfs.ko` (manual loading)
- **After**: Automatically runs at `late_initcall` during boot
- **Status**: Check `/sys/kernel/boot_certs/ok` after boot

## Boot Sequence Timing

```
Kernel Boot Sequence:
  1. early_initcall      - Early platform init
  2. core_initcall       - Core kernel subsystems
  3. postcore_initcall   - Post-core initialization
  4. arch_initcall       - Architecture-specific init
  5. subsys_initcall     - Subsystem initialization
  6. fs_initcall         - Filesystem type registration
  7. rootfs_initcall     - Root filesystem mounting
  8. device_initcall     - Device drivers
  ↓
  9. late_initcall       ← BOOT_CERTS RUNS HERE
  ↓
  10. Module loading     ← Protected by boot certs
```

**Rationale for late_initcall**:
- Runs **after** `rootfs_initcall` (filesystem infrastructure ready)
- Runs **after** initramfs unpacking (boot partition mounted)
- Runs **before** `device_initcall` (most drivers)
- Runs **before** module loading begins

## Configuration

### Kernel menuconfig

```bash
cd /home/hs/linux-rpi
make menuconfig

# Navigate to:
Security options --->
  [*] Boot certificate validation and keyring sealing

# Configure sub-options:
  [*] Seal .secondary_trusted_keys at boot
  [*] Allow one-way sealing via /sys/kernel/boot_certs/sealed
  (262144) Max bytes for chain.pem

  Certificate expiry policy --->
    ( ) Warn only (log to dmesg)
    (X) Reject expired certificates  ← Recommended
    ( ) Reject certificates expiring soon (strict mode)

  (30) Grace period for expiry warnings (days)
  [*] Enable daily certificate expiry checks
  (24) Certificate expiry check interval (hours)
```

### Dependencies

The feature automatically selects:
- `CRYPTO` - Cryptographic framework
- `CRYPTO_HASH` - Hash algorithms
- `CRYPTO_SHA3` - SHA3-512 hashing
- `BASE64` - Base64 encoding/decoding

Required dependencies:
- `SYSFS` - Sysfs filesystem
- `KEYS` - Kernel key retention service
- `SECONDARY_TRUSTED_KEYRING` - Secondary trusted keyring

## Building

### Full Kernel Build

```bash
cd /home/hs/linux-rpi

# Configure (first time or to change options)
make menuconfig

# Build kernel with boot_certs built-in
make -j$(nproc)

# Install
sudo make install
sudo reboot
```

### Incremental Build (after code changes)

```bash
cd /home/hs/linux-rpi

# Rebuild security subsystem
make security/

# Or rebuild just boot_certs
make security/boot_certs/boot_certs_sysfs.o

# Rebuild kernel image
make -j$(nproc)

# Install
sudo make install
sudo reboot
```

## Verification After Boot

### Check if Boot Certs Loaded

```bash
# Should show "true" if validation succeeded
cat /sys/kernel/boot_certs/ok

# Detailed status
cat /sys/kernel/boot_certs/status

# Should show "true" if keyrings sealed
cat /sys/kernel/boot_certs/sealed

# Check expiry status
cat /sys/kernel/boot_certs/expiry_status
```

### Check Kernel Boot Messages

```bash
# Look for boot_certs messages
dmesg | grep boot_certs

# Expected output (success):
# [    X.XXXXXX] boot_certs: loaded 2 certificate(s)
# [    X.XXXXXX] boot_certs: 1 root CA(s) added to .boot_root_certs
# [    X.XXXXXX] boot_certs: 1 intermediate(s) added to .secondary_trusted_keys
# [    X.XXXXXX] boot_certs: keyrings sealed
# [    X.XXXXXX] boot_certs: OK, exported 4096 bytes to /sys/kernel/boot_certs/chain.pem
```

### Check Keyrings

```bash
# List boot root certs keyring (should be sealed)
keyctl show @boot_root_certs

# List secondary trusted keys (should contain all certs)
keyctl show @s

# Try to add a key (should fail - keyring sealed)
echo "test" | sudo keyctl padd asymmetric "test" @boot_root_certs
# Expected: add_key: Permission denied
```

## Boot Partition Requirements

### Current Implementation (Filesystem-based)

The system expects:
- **Path**: `/boot/firmware/certs/chain.pem`
- **Format**: PEM-encoded certificate chain (root first, then intermediates)
- **Hash**: SHA3-512 hash must match kernel cmdline parameter `boot_certs.sha3=...`
- **Filesystem**: Must be read-only when chain.pem is accessed

### Kernel Cmdline Setup

```bash
# Calculate hash
openssl dgst -sha3-512 /boot/firmware/certs/chain.pem
# Output: SHA3-512(...)= <128 hex chars>

# Add to kernel cmdline
# Edit /boot/firmware/cmdline.txt or config.txt:
boot_certs.sha3=<128 hex chars from above>
```

### Future Migration (Secure Element)

**Planned**: Replace filesystem-based loading with secure element storage:
- **TPM 2.0**: Store certificates in TPM NV indices
- **Secure Element**: Hardware-based certificate storage
- **Benefits**:
  - No dependency on filesystem mounting
  - Hardware-protected storage
  - Measured boot integration
  - No /boot/firmware required

**Migration path**: Code structure allows swapping `bc_read_boot_file()` for secure element read function without affecting rest of the system.

## Testing

### Unit Tests (Still Use Module for Testing)

The test suite works independently:

```bash
cd /home/hs/linux-rpi/security/boot_certs/tests

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run unit tests (no kernel interaction)
./run_tests.sh
```

### Integration Tests (Kernel Built-in)

**IMPORTANT**: Integration tests check `/sys/kernel/boot_certs/` which is created by the built-in code at boot.

```bash
# After booting with built-in boot_certs enabled:
cd /home/hs/linux-rpi/security/boot_certs/tests

# Run integration tests (requires root)
sudo ./run_tests.sh --all
```

Expected results:
- ✅ All 18 tests should pass (11 unit + 7 integration)
- If expiry_status missing: Old kernel without expiry features (rebuild needed)

## Troubleshooting

### Boot Fails: Cannot Find chain.pem

**Problem**: Boot partition not mounted or wrong path.

**Check**:
```bash
# Boot into recovery mode
ls -la /boot/firmware/certs/

# Verify chain.pem exists
cat /boot/firmware/certs/chain.pem
```

**Solution**: Ensure initramfs or early userspace mounts boot partition before late_initcall.

### Boot Fails: Hash Mismatch

**Problem**: SHA3-512 hash doesn't match.

**Solution**:
```bash
# Recalculate hash
openssl dgst -sha3-512 /boot/firmware/certs/chain.pem

# Update kernel cmdline with correct hash
# Edit /boot/firmware/cmdline.txt
```

### Boot Fails: Certificate Expired

**Problem**: Certificate expiry policy is REJECT or STRICT and cert is expired.

**Solutions**:
1. **Temporary**: Change policy to WARN in menuconfig and rebuild
2. **Permanent**: Generate new certificates and update chain.pem

### Sysfs Files Missing

**Problem**: `/sys/kernel/boot_certs/` doesn't exist.

**Check**:
```bash
# Verify CONFIG_BOOT_CERTS_SYSFS is enabled
grep CONFIG_BOOT_CERTS_SYSFS /boot/config-$(uname -r)
# Should show: CONFIG_BOOT_CERTS_SYSFS=y

# Check kernel messages
dmesg | grep boot_certs
```

**Solution**: Rebuild kernel with `CONFIG_BOOT_CERTS_SYSFS=y`

### Integration Tests Fail

**Problem**: Some tests fail with "expiry_status not found".

**Cause**: Running old kernel without expiry features.

**Solution**: Rebuild and install new kernel with all features.

## Migration Checklist

If migrating from module to built-in:

- [ ] Configure kernel: `CONFIG_BOOT_CERTS_SYSFS=y`
- [ ] Build kernel: `make -j$(nproc)`
- [ ] Install kernel: `sudo make install`
- [ ] Verify boot partition: `/boot/firmware/certs/chain.pem` exists
- [ ] Verify cmdline: `boot_certs.sha3=...` parameter present
- [ ] Reboot
- [ ] Check status: `cat /sys/kernel/boot_certs/ok` → should show `true`
- [ ] Check keyrings: `keyctl show @boot_root_certs`
- [ ] Run tests: `cd tests && sudo ./run_tests.sh --all`

## Files Modified

| File | Change |
|------|--------|
| `security/boot_certs/Kconfig` | `tristate` → `bool`, updated help text |
| `security/boot_certs/boot_certs_sysfs.c` | Removed module.h, MODULE_* macros, changed to late_initcall |
| `security/boot_certs/Makefile` | No change (already uses `obj-$(CONFIG_BOOT_CERTS_SYSFS)`) |
| `security/Makefile` | No change (already includes boot_certs/) |
| `security/Kconfig` | No change (already sources boot_certs/Kconfig) |

## Documentation Updates Needed

- [x] README.md - Update build instructions (built-in, not module)
- [x] BUILTIN_MIGRATION.md - This document
- [ ] IMPLEMENTATION_COMPLETE.md - Update "module" references to "built-in"
- [ ] tests/README.md - Clarify that integration tests require built-in kernel

## Summary

The boot certificate system is now **built-in kernel code** that:
- Runs automatically at boot (`late_initcall`)
- Validates certificate chain before module loading
- Cannot be bypassed or prevented from loading
- Provides root of trust for module signature verification
- Will migrate to secure element storage (removing filesystem dependency)

This aligns with security best practices and makes the system production-ready.
