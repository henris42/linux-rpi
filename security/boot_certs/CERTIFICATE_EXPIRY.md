# Certificate Expiry Enforcement

## Overview

The boot_certs system now includes comprehensive certificate expiry checking with configurable policies and automated monitoring. This ensures your boot chain certificates remain valid and provides early warning before expiry.

## Features

✅ **Multi-level checking**
- Boot-time validation
- Runtime checks when adding new certificates
- Periodic automated checks (daily by default)
- Manual trigger via sysfs

✅ **Configurable policies**
- WARN - Log warnings but allow expired certificates
- REJECT - Block expired certificates
- STRICT - Block certificates expiring within grace period

✅ **Comprehensive visibility**
- sysfs interface for status monitoring
- dmesg logging
- Integration with monitoring tools

## Configuration (Kconfig)

### Expiry Policy

Choose your enforcement policy at compile time:

```kconfig
CONFIG_BOOT_CERTS_EXPIRY_WARN=y     # Log warnings only (default)
CONFIG_BOOT_CERTS_EXPIRY_REJECT=y   # Reject expired certificates
CONFIG_BOOT_CERTS_EXPIRY_STRICT=y   # Reject if expiring within grace period
```

**Recommended for production:** `CONFIG_BOOT_CERTS_EXPIRY_REJECT=y`

### Grace Period

Set the warning threshold for certificates expiring soon:

```kconfig
CONFIG_BOOT_CERTS_EXPIRY_GRACE_DAYS=30  # Default: 30 days
```

In STRICT mode, certificates expiring within this period are rejected.
In REJECT/WARN modes, warnings are logged but certificates are still accepted.

### Periodic Checks

Enable automated periodic checking:

```kconfig
CONFIG_BOOT_CERTS_EXPIRY_CHECK_DAILY=y           # Enable periodic checks
CONFIG_BOOT_CERTS_EXPIRY_CHECK_INTERVAL=24       # Check every 24 hours
```

## Policy Comparison

| Policy | Expired Certs | Expiring Soon | Boot Failure | Use Case |
|--------|---------------|---------------|--------------|----------|
| **WARN** | ⚠️ Log warning | ⚠️ Log warning | ❌ No | Testing, debugging |
| **REJECT** | ❌ Reject | ⚠️ Log warning | ✅ Yes | Production (recommended) |
| **STRICT** | ❌ Reject | ❌ Reject | ✅ Yes | High-security environments |

### Policy Details

#### WARN Mode
```
✅ Allows expired certificates
⚠️  Logs warnings to dmesg
📊 Suitable for development/testing
⚠️  NOT recommended for production
```

**Example dmesg output:**
```
boot_certs: 1 expired certificate(s) found (WARN mode)
boot_certs: 2 certificate(s) expiring within 30 days
```

#### REJECT Mode
```
❌ Blocks expired certificates
⚠️  Warns about expiring certificates
✅ Recommended for production
📊 Allows time for certificate rotation
```

**Example dmesg output (expired cert):**
```
boot_certs: 1 expired certificate(s) - REJECTING (policy=REJECT)
boot_certs: failed: violation=certificate_expired
```

**Example dmesg output (expiring soon):**
```
boot_certs: 2 certificate(s) expiring within 30 days
boot_certs: OK, exported 4096 bytes...
```

#### STRICT Mode
```
❌ Blocks expired certificates
❌ Blocks certificates expiring within grace period
🔒 Maximum security
⚡ Requires proactive certificate rotation
```

**Example dmesg output:**
```
boot_certs: 1 certificate(s) expiring within 30 days - REJECTING (policy=STRICT)
boot_certs: failed: violation=certificate_expiring_soon
```

## Runtime Monitoring

### Check Expiry Status

View current expiry status via sysfs:

```bash
cat /sys/kernel/boot_certs/expiry_status
```

**Example output:**
```
policy=REJECT grace_days=30 expired=0 expiring_soon=1 last_check=1739367890 earliest_expiry_days=45 check_enabled=1
```

**Field descriptions:**
- `policy` - Current enforcement policy (WARN/REJECT/STRICT)
- `grace_days` - Grace period in days
- `expired` - Number of currently expired certificates
- `expiring_soon` - Number of certificates expiring within grace period
- `last_check` - Unix timestamp of last expiry check
- `earliest_expiry_days` - Days until first certificate expires (negative = already expired)
- `check_enabled` - Whether periodic checks are enabled (0/1)

### Manual Expiry Check

Trigger an immediate expiry check:

```bash
echo 1 > /sys/kernel/boot_certs/expiry_check_now
```

This updates the expiry status and logs results to dmesg:

```
boot_certs: manual expiry check: expired=0 expiring_soon=2
```

### View Overall Status

Check the main status including violations:

```bash
cat /sys/kernel/boot_certs/status
```

Look for `violation=` field:
- `violation=none` - All good
- `violation=certificate_expired` - Expired cert detected
- `violation=certificate_expiring_soon` - Cert expiring soon (STRICT mode)

## Monitoring and Alerting

### Systemd Service for Monitoring

Create `/etc/systemd/system/boot-certs-monitor.service`:

```ini
[Unit]
Description=Boot Certificates Expiry Monitor
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/check-boot-certs-expiry.sh

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/boot-certs-monitor.timer`:

```ini
[Unit]
Description=Daily Boot Certificates Expiry Check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Create `/usr/local/bin/check-boot-certs-expiry.sh`:

```bash
#!/bin/bash
# Boot certificates expiry monitoring script

EXPIRY_STATUS="/sys/kernel/boot_certs/expiry_status"
ALERT_EMAIL="admin@example.com"

if [ ! -f "$EXPIRY_STATUS" ]; then
    echo "ERROR: boot_certs not loaded"
    exit 1
fi

# Trigger manual check
echo 1 > /sys/kernel/boot_certs/expiry_check_now 2>/dev/null

# Read status
STATUS=$(cat "$EXPIRY_STATUS")
EXPIRED=$(echo "$STATUS" | grep -oP 'expired=\K\d+')
EXPIRING_SOON=$(echo "$STATUS" | grep -oP 'expiring_soon=\K\d+')
DAYS_UNTIL=$(echo "$STATUS" | grep -oP 'earliest_expiry_days=\K-?\d+')

# Alert if problems detected
if [ "$EXPIRED" -gt 0 ]; then
    echo "CRITICAL: $EXPIRED boot certificate(s) expired!" | \
        mail -s "Boot Certificate EXPIRED" "$ALERT_EMAIL"
    exit 2
fi

if [ "$EXPIRING_SOON" -gt 0 ]; then
    echo "WARNING: $EXPIRING_SOON boot certificate(s) expiring soon (within $DAYS_UNTIL days)" | \
        mail -s "Boot Certificate Expiring Soon" "$ALERT_EMAIL"
    exit 1
fi

echo "OK: All boot certificates valid (earliest expiry in $DAYS_UNTIL days)"
exit 0
```

Enable the timer:

```bash
chmod +x /usr/local/bin/check-boot-certs-expiry.sh
systemctl daemon-reload
systemctl enable boot-certs-monitor.timer
systemctl start boot-certs-monitor.timer
```

### Nagios/Icinga Plugin

Create `/usr/lib/nagios/plugins/check_boot_certs`:

```bash
#!/bin/bash
# Nagios/Icinga plugin for boot certificates expiry

EXPIRY_STATUS="/sys/kernel/boot_certs/expiry_status"
WARN_DAYS=${1:-60}
CRIT_DAYS=${2:-30}

if [ ! -f "$EXPIRY_STATUS" ]; then
    echo "UNKNOWN: boot_certs not loaded"
    exit 3
fi

STATUS=$(cat "$EXPIRY_STATUS")
EXPIRED=$(echo "$STATUS" | grep -oP 'expired=\K\d+')
EXPIRING_SOON=$(echo "$STATUS" | grep -oP 'expiring_soon=\K\d+')
DAYS_UNTIL=$(echo "$STATUS" | grep -oP 'earliest_expiry_days=\K-?\d+')

if [ "$EXPIRED" -gt 0 ]; then
    echo "CRITICAL: $EXPIRED certificate(s) expired"
    exit 2
fi

if [ "$DAYS_UNTIL" -lt "$CRIT_DAYS" ]; then
    echo "CRITICAL: Certificate expiring in $DAYS_UNTIL days (< $CRIT_DAYS)"
    exit 2
fi

if [ "$DAYS_UNTIL" -lt "$WARN_DAYS" ]; then
    echo "WARNING: Certificate expiring in $DAYS_UNTIL days (< $WARN_DAYS)"
    exit 1
fi

echo "OK: Earliest expiry in $DAYS_UNTIL days | days_until=$DAYS_UNTIL"
exit 0
```

Usage in Nagios:

```
define command {
    command_name    check_boot_certs
    command_line    /usr/lib/nagios/plugins/check_boot_certs 60 30
}
```

### Prometheus Exporter

Create `/usr/local/bin/boot_certs_exporter.sh`:

```bash
#!/bin/bash
# Prometheus node exporter textfile collector for boot certificates

TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
EXPIRY_STATUS="/sys/kernel/boot_certs/expiry_status"
OUTPUT="$TEXTFILE_DIR/boot_certs.prom.$$"

if [ ! -f "$EXPIRY_STATUS" ]; then
    exit 1
fi

STATUS=$(cat "$EXPIRY_STATUS")
EXPIRED=$(echo "$STATUS" | grep -oP 'expired=\K\d+')
EXPIRING_SOON=$(echo "$STATUS" | grep -oP 'expiring_soon=\K\d+')
DAYS_UNTIL=$(echo "$STATUS" | grep -oP 'earliest_expiry_days=\K-?\d+')

cat > "$OUTPUT" <<EOF
# HELP boot_certs_expired_count Number of expired boot certificates
# TYPE boot_certs_expired_count gauge
boot_certs_expired_count $EXPIRED

# HELP boot_certs_expiring_soon_count Number of boot certificates expiring soon
# TYPE boot_certs_expiring_soon_count gauge
boot_certs_expiring_soon_count $EXPIRING_SOON

# HELP boot_certs_earliest_expiry_days Days until earliest certificate expiry
# TYPE boot_certs_earliest_expiry_days gauge
boot_certs_earliest_expiry_days $DAYS_UNTIL
EOF

mv "$OUTPUT" "$TEXTFILE_DIR/boot_certs.prom"
```

Add to crontab:

```bash
*/5 * * * * /usr/local/bin/boot_certs_exporter.sh
```

Prometheus alert rules:

```yaml
groups:
  - name: boot_certs
    rules:
      - alert: BootCertificateExpired
        expr: boot_certs_expired_count > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Boot certificate expired"
          description: "{{ $value }} boot certificate(s) have expired"

      - alert: BootCertificateExpiringSoon
        expr: boot_certs_earliest_expiry_days < 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Boot certificate expiring soon"
          description: "Boot certificate expires in {{ $value }} days"
```

## Certificate Rotation Workflow

### 1. Monitor Expiry

Check current status:

```bash
cat /sys/kernel/boot_certs/expiry_status
```

### 2. Generate New Certificates

When certificates are expiring (e.g., within 60 days):

```bash
# Generate new root CA (if needed)
openssl ecparam -out new_root.key -name secp384r1 -genkey
openssl req -x509 -new -key new_root.key -out new_root.pem -days 3650 \
    -subj "/C=US/O=YourOrg/CN=Root CA v2"

# Generate new intermediate CA
openssl ecparam -out new_int.key -name secp384r1 -genkey
openssl req -new -key new_int.key -out new_int.csr \
    -subj "/C=US/O=YourOrg/CN=Intermediate CA v2"

openssl x509 -req -in new_int.csr -CA new_root.pem -CAkey new_root.key \
    -CAcreateserial -out new_int.pem -days 1825 \
    -extensions v3_ca -extfile <(echo "[v3_ca]
basicConstraints=CA:TRUE
keyUsage=keyCertSign,cRLSign")
```

### 3. Create New Chain

```bash
# Combine into chain (root first, then intermediates)
cat new_root.pem new_int.pem > /tmp/new_chain.pem
```

### 4. Update Boot Partition

```bash
# Calculate new hash
NEW_HASH=$(openssl dgst -sha3-512 /tmp/new_chain.pem | awk '{print $2}')

# Update chain on boot partition
sudo mount -o remount,rw /boot/firmware
sudo cp /tmp/new_chain.pem /boot/firmware/certs/chain.pem
sudo mount -o remount,ro /boot/firmware

# Update kernel cmdline (in config.txt or cmdline.txt)
# Replace boot_certs.sha3=OLD_HASH with boot_certs.sha3=$NEW_HASH
```

### 5. Reboot and Verify

```bash
sudo reboot

# After reboot, check status
cat /sys/kernel/boot_certs/expiry_status
# Should show: expired=0 expiring_soon=0
```

## Troubleshooting

### Boot Failure: Certificate Expired

**Symptom:** System won't boot, dmesg shows:
```
boot_certs: 1 expired certificate(s) - REJECTING (policy=REJECT)
```

**Solution:**

1. Boot into recovery mode or from USB
2. Mount boot partition:
   ```bash
   mount /dev/mmcblk0p1 /mnt/boot
   ```
3. Update chain.pem with valid certificates
4. Recalculate hash and update kernel cmdline
5. Reboot

**Emergency bypass** (temporary):

Recompile kernel with `CONFIG_BOOT_CERTS_EXPIRY_WARN=y` to allow boot with expired certs (logs warnings only).

### False Positive: Time Sync Issues

**Symptom:** Certificates reported as expired but are actually valid

**Cause:** System clock is incorrect (RTC battery dead, no NTP)

**Solution:**

1. Check system time:
   ```bash
   date
   timedatectl status
   ```

2. Sync with NTP:
   ```bash
   timedatectl set-ntp true
   systemctl restart systemd-timesyncd
   ```

3. If no network, set time manually:
   ```bash
   timedatectl set-time "2026-02-12 10:30:00"
   ```

4. Re-check expiry:
   ```bash
   echo 1 > /sys/kernel/boot_certs/expiry_check_now
   cat /sys/kernel/boot_certs/expiry_status
   ```

### Certificates Appear Valid But Failing

**Symptom:** OpenSSL shows certificate as valid, but kernel rejects it

**Possible causes:**

1. **Time zone mismatch** - Kernel uses UTC
   ```bash
   # Check cert validity in UTC
   TZ=UTC openssl x509 -in cert.pem -noout -dates
   ```

2. **Grace period** (STRICT mode) - Certificate valid but expires within grace period
   ```bash
   # Check expiry status
   cat /sys/kernel/boot_certs/expiry_status
   # If expiring_soon > 0, certificate expires within grace_days
   ```

3. **Parsing error** - Kernel couldn't extract validity dates
   ```bash
   # Check dmesg for parsing errors
   dmesg | grep boot_certs
   ```

## Best Practices

### Certificate Lifecycle Management

1. **Plan ahead**
   - Root CA: 10 years validity
   - Intermediate CA: 5 years validity
   - End-entity certs: 1-2 years validity

2. **Rotation schedule**
   - Rotate intermediates before they expire
   - Keep root CA offline, use sparingly
   - Start rotation when earliest_expiry_days < 90

3. **Monitoring**
   - Set up automated alerts (see Monitoring section)
   - Check expiry status in CI/CD pipelines
   - Include in regular security audits

4. **Policy selection**
   - Development: WARN mode
   - Staging: REJECT mode
   - Production: REJECT mode (or STRICT for high-security)

### Production Recommendations

```kconfig
# Production-grade configuration
CONFIG_BOOT_CERTS_EXPIRY_REJECT=y
CONFIG_BOOT_CERTS_EXPIRY_GRACE_DAYS=60
CONFIG_BOOT_CERTS_EXPIRY_CHECK_DAILY=y
CONFIG_BOOT_CERTS_EXPIRY_CHECK_INTERVAL=24
```

This configuration:
- ✅ Blocks expired certificates (REJECT mode)
- ⚠️  Warns 60 days before expiry
- 📅 Checks daily for expired/expiring certificates
- 🔒 Maintains security while allowing time for rotation

## API Reference

### Sysfs Interface

| Path | Type | Description |
|------|------|-------------|
| `/sys/kernel/boot_certs/expiry_status` | RO | Current expiry status |
| `/sys/kernel/boot_certs/expiry_check_now` | WO | Trigger manual check (write "1") |
| `/sys/kernel/boot_certs/status` | RO | Overall status including violations |

### Status Fields

`expiry_status` output format:
```
policy=<WARN|REJECT|STRICT> grace_days=<N> expired=<N> expiring_soon=<N> last_check=<unix_time> earliest_expiry_days=<N> check_enabled=<0|1>
```

## See Also

- [KEYRING_SEALING.md](KEYRING_SEALING.md) - Hierarchical trust model
- [SOLUTION_SUMMARY.md](SOLUTION_SUMMARY.md) - Quick start guide
- [README.md](README.md) - Basic usage

## Support

For issues or questions:
- Check dmesg: `dmesg | grep boot_certs`
- Review Kconfig: `make menuconfig` → Security options → Boot Certificates
- File bug report with expiry_status output and dmesg logs
