# boot_certs_sysfs

Export a boot certificate chain via sysfs with strong immutability guarantees, hierarchical keyring sealing, and certificate expiry enforcement.

> **⚠️ IMPORTANT**: This is **built-in kernel code**, not a loadable module. Certificate validation must occur before third-party modules are loaded. See [BUILTIN_MIGRATION.md](BUILTIN_MIGRATION.md) for details.

## Features

✅ **Boot Chain Validation**
- Built into kernel (not a module) for early boot validation
- Reads `<boot>/certs/chain.pem` at late_initcall (before module loading)
- Verifies SHA3-512 hash against kernel cmdline parameter
- Requires backing filesystem to be read-only
- Exposes certificate chain via `/sys/kernel/boot_certs/chain.pem`

✅ **Hierarchical Keyring Sealing** (Unique feature)
- Separate `.boot_root_certs` and `.secondary_trusted_keys` keyrings
- Root CAs locked and immutable after boot
- New intermediate CAs can be added if signed by roots
- Prevents unauthorized root CA additions

✅ **Certificate Expiry Enforcement**
- Three configurable policies: WARN, REJECT, STRICT
- Boot-time and runtime validation
- Automated daily checking via workqueue
- Monitoring via sysfs interface

## Quick Start

**IMPORTANT**: Boot certificate validation is built into the kernel (not a loadable module). This ensures validation occurs before third-party modules are loaded.

### 1. Build Kernel

```bash
cd /home/hs/linux-rpi

# Configure kernel
make menuconfig
# Navigate to: Security options → Boot certificate validation and keyring sealing
# Select: [*] Boot certificate validation and keyring sealing  ← Must be [*] not [M]
#         [*] Seal .secondary_trusted_keys at boot
#         Certificate expiry policy → (•) Reject expired certificates
#         (30) Grace period for expiry warnings (days)
#         [*] Enable daily certificate expiry checks

# Build kernel (boot_certs built-in)
make -j$(nproc)

# Install and reboot
sudo make install
sudo reboot
```

### 2. Prepare Boot Certificates

```bash
# Create certificate chain (root first, then intermediates)
cat root_ca.pem intermediate_ca.pem > /boot/firmware/certs/chain.pem

# Calculate SHA3-512 hash
openssl dgst -sha3-512 /boot/firmware/certs/chain.pem
# Output: SHA3-512(...)= <128 hex chars>

# Add to kernel cmdline (in /boot/firmware/cmdline.txt or config.txt)
# Add: boot_certs.sha3=<128 hex chars>
```

### 3. Verify After Boot

Boot certificate validation runs automatically at `late_initcall` during kernel boot. No manual loading required.

```bash
# After reboot, check status
cat /sys/kernel/boot_certs/ok          # Should show: true
cat /sys/kernel/boot_certs/sealed      # Should show: true
cat /sys/kernel/boot_certs/expiry_status

# Check kernel boot messages
dmesg | grep boot_certs

# Expected output:
# boot_certs: loaded 2 certificate(s)
# boot_certs: 1 root CA(s) added to .boot_root_certs
# boot_certs: OK, exported XXXX bytes to /sys/kernel/boot_certs/chain.pem
```

## Testing

### Run Test Suite

```bash
cd tests

# Setup (one-time)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run unit tests (no root required)
./run_tests.sh

# Run all tests including kernel integration (requires root + built-in kernel)
# Boot with CONFIG_BOOT_CERTS_SYSFS=y first, then run:
sudo ./run_tests.sh --all
```

See [tests/README.md](tests/README.md) for detailed test documentation.

### Manual Testing

```bash
# After booting with boot_certs built-in, check basic functionality
cat /sys/kernel/boot_certs/ok          # true if validation passed
cat /sys/kernel/boot_certs/status      # Detailed status
cat /sys/kernel/boot_certs/sealed      # true if keyrings sealed

# Check expiry status
cat /sys/kernel/boot_certs/expiry_status
# Output: policy=REJECT grace_days=30 expired=0 expiring_soon=0 ...

# Trigger manual expiry check
echo 1 | sudo tee /sys/kernel/boot_certs/expiry_check_now
dmesg | tail

# View keyrings
keyctl show @boot_root_certs           # Root CAs only
keyctl show @s                         # All certs (roots + intermediates)
```

## Runtime Operations

### Add New Intermediate CA

```bash
# Create intermediate CA signed by your root CA
openssl req -new -key intermediate.key -out intermediate.csr \
    -subj "/C=US/O=YourOrg/CN=New Intermediate CA"

openssl x509 -req -in intermediate.csr \
    -CA /boot/firmware/certs/root_ca.pem \
    -CAkey /boot/firmware/certs/root_ca.key \
    -out intermediate.pem -days 365 \
    -extensions v3_ca

# Convert to DER
openssl x509 -in intermediate.pem -outform DER -out intermediate.der

# Add to keyring (requires root signed, will fail otherwise)
sudo keyctl padd asymmetric "new_intermediate" @s < intermediate.der
```

### Monitor Certificate Expiry

```bash
# Read current expiry status
cat /sys/kernel/boot_certs/expiry_status

# Manual expiry check
echo 1 | sudo tee /sys/kernel/boot_certs/expiry_check_now

# Set up monitoring (see CERTIFICATE_EXPIRY.md for Prometheus/Nagios examples)
```

## Configuration (Kconfig)

### Expiry Policy Options

```kconfig
CONFIG_BOOT_CERTS_EXPIRY_WARN=y            # Log warnings only
CONFIG_BOOT_CERTS_EXPIRY_REJECT=y          # Reject expired (recommended)
CONFIG_BOOT_CERTS_EXPIRY_STRICT=y          # Reject expiring soon
CONFIG_BOOT_CERTS_EXPIRY_GRACE_DAYS=30     # Grace period (1-365 days)
CONFIG_BOOT_CERTS_EXPIRY_CHECK_DAILY=y     # Enable periodic checks
CONFIG_BOOT_CERTS_EXPIRY_CHECK_INTERVAL=24 # Check interval (hours)
```

### Keyring Sealing Options

```kconfig
CONFIG_BOOT_CERTS_SEAL_AT_BOOT=y           # Seal at boot
CONFIG_BOOT_CERTS_ALLOW_SYSFS_SEAL=y       # Allow manual sealing via sysfs
```

## Documentation

- **[BUILTIN_MIGRATION.md](BUILTIN_MIGRATION.md)** - **Built-in kernel code explanation** ⭐
- [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) - Complete feature overview
- [KEYRING_SEALING.md](KEYRING_SEALING.md) - Hierarchical trust model details
- [CERTIFICATE_EXPIRY.md](CERTIFICATE_EXPIRY.md) - Expiry enforcement guide
- [SOLUTION_SUMMARY.md](SOLUTION_SUMMARY.md) - Quick start and testing
- [tests/README.md](tests/README.md) - Test suite documentation
- [tests/TEST_SUITE_SUMMARY.md](tests/TEST_SUITE_SUMMARY.md) - Test quick reference

## Creating CSRs and Certificates

### Generate Root CA

```bash
# Generate EC private key (secp384r1)
openssl ecparam -out root_ca.key -name secp384r1 -genkey

# Create self-signed root CA
openssl req -x509 -new -key root_ca.key -out root_ca.pem -days 3650 \
    -subj "/C=US/O=YourOrg/CN=Root CA" \
    -extensions v3_ca
```

### Generate Intermediate CA

```bash
# Generate key
openssl ecparam -out intermediate.key -name secp384r1 -genkey

# Create CSR
openssl req -new -key intermediate.key -out intermediate.csr \
    -subj "/C=US/O=YourOrg/CN=Intermediate CA"

# Sign with root CA
openssl x509 -req -in intermediate.csr \
    -CA root_ca.pem -CAkey root_ca.key \
    -CAcreateserial -out intermediate.pem -days 1825 \
    -extensions v3_ca -extfile <(echo "[v3_ca]
basicConstraints=CA:TRUE
keyUsage=keyCertSign,cRLSign")
```

## Troubleshooting

### Boot Failure: Hash Mismatch

```bash
# Recalculate hash
openssl dgst -sha3-512 /boot/firmware/certs/chain.pem

# Update kernel cmdline with correct hash
# Edit /boot/firmware/cmdline.txt or config.txt
```

### Boot Failure: Certificate Expired

```bash
# Check certificate expiry
openssl x509 -in /boot/firmware/certs/chain.pem -noout -dates

# If expired, generate new certificates and update chain.pem
# See CERTIFICATE_EXPIRY.md for rotation workflow
```

### Module Won't Load

```bash
# Check dmesg for errors
dmesg | grep boot_certs

# Common issues:
# - SHA3-512 hash mismatch
# - Filesystem not read-only
# - Invalid PEM format
# - Expired certificates (in REJECT/STRICT mode)
```

## Openssl changes
PQ provider needs to be added, see https://github.com/henris42/oqs-provider/tree/falcon1024old-oid
Also add to openssl config (ie /etc/ssl/openssl.cnf):
```
# List of providers to load
[provider_sect]
oqsprovider = oqsprovider_sect
default = default_sect
[default_sect]
activate = 1
[oqsprovider_sect]
activate = 1

```

## Support

For issues, check:
1. `dmesg | grep boot_certs` - Kernel messages
2. `/sys/kernel/boot_certs/status` - Detailed status
3. Documentation in this directory
4. Test suite output: `cd tests && ./run_tests.sh`