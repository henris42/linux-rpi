# Hierarchical Keyring Sealing Solution

## Problem Statement

The goal is to:
1. Lock root certificates in the keyring so they're immutable
2. Allow new intermediate CA certificates to be added, as long as they're signed by a root CA
3. Prevent new root CA certificates from being added after sealing

## Solution Architecture

### Two-Keyring Approach

We use **two separate keyrings** with different trust levels:

1. **`.boot_root_certs`** - Contains ONLY self-signed root CA certificates
   - Sealed with `restrict_link_reject` (no new keys allowed at all)
   - Acts as the trust anchor

2. **`.secondary_trusted_keys`** - Contains ALL certificates (roots + intermediates)
   - Restricted to only accept new certs signed by keys in `.boot_root_certs`
   - Used for actual kernel module signature verification

### How It Works

#### Phase 1: Boot-time Loading

```c
// 1. Parse chain.pem and extract certificates
bc_pem_extract_all();

// 2. Identify root CAs (where subject == issuer)
for each cert:
    if (cert.issuer == cert.subject):
        // This is a root CA
        boot_root_certs_add_cert()          // Add to .boot_root_certs
        secondary_trusted_keys_add_cert()    // Also add to .secondary_trusted_keys
    else:
        // This is an intermediate CA
        secondary_trusted_keys_add_cert()    // Add only to .secondary_trusted_keys
```

#### Phase 2: Sealing

```c
secondary_trusted_keys_seal() {
    // Step 1: Seal boot_root_certs (no new roots allowed)
    keyring_restrict(boot_root_certs, NULL, NULL);  // Complete lockdown

    // Step 2: Restrict secondary to only accept certs signed by boot roots
    snprintf(restr, "key_or_keyring:%u", boot_root_certs->serial);
    keyring_restrict(secondary_trusted_keys, "asymmetric", restr);
}
```

### Key Insight: `key_or_keyring` vs `key_or_keyring_chain`

The critical difference is in the restriction function:

- **`restrict_link_by_key_or_keyring`** - Validates new certs against the **trusted keyring only**
  - New cert must be signed by a key in `boot_root_certs`
  - Does NOT check keys already in `secondary_trusted_keys`
  - ✅ This is what we want!

- **`restrict_link_by_key_or_keyring_chain`** - Validates against **both** trusted keyring AND destination keyring
  - New cert can be signed by ANY key in `secondary_trusted_keys` (including intermediates)
  - ❌ Too permissive for our use case

## Trust Model

```
┌─────────────────────────────┐
│   .boot_root_certs          │
│   (SEALED - no new roots)   │
│                             │
│   ┌─────────────────┐       │
│   │  Root CA #1     │       │
│   │  (self-signed)  │◄──────┼─── Trust Anchor
│   └─────────────────┘       │
│   ┌─────────────────┐       │
│   │  Root CA #2     │       │
│   │  (self-signed)  │       │
│   └─────────────────┘       │
└──────────┬──────────────────┘
           │
           │ Can sign new certs
           ▼
┌─────────────────────────────┐
│  .secondary_trusted_keys    │
│  (accepts certs signed by   │
│   boot_root_certs only)     │
│                             │
│  ┌─────────────────┐        │
│  │  Root CA #1     │        │
│  └─────────────────┘        │
│  ┌─────────────────┐        │
│  │  Root CA #2     │        │
│  └─────────────────┘        │
│  ┌─────────────────┐        │
│  │  Intermediate   │◄────── Signed by Root CA #1
│  │  CA #1          │        │
│  └─────────────────┘        │
│  ┌─────────────────┐        │
│  │  Intermediate   │◄────── Signed by Root CA #2
│  │  CA #2          │        │
│  └─────────────────┘        │
│                             │
│  ┌─────────────────┐        │
│  │  New Cert       │◄────── Can be added if signed by Root CA
│  │  (runtime)      │        │  (but NOT by Intermediate CA)
│  └─────────────────┘        │
└─────────────────────────────┘
           │
           │ Used for
           ▼
    Module Signature
     Verification
```

## Runtime Behavior

### ✅ Allowed Operations After Sealing

1. **Add new intermediate CA signed by root**
   ```bash
   # This works - signed by a root CA in boot_root_certs
   keyctl padd asymmetric "new_intermediate" @s < new_intermediate.der
   ```

2. **Add end-entity cert signed by root**
   ```bash
   # This works - signed by a root CA
   keyctl padd asymmetric "new_module_cert" @s < module_cert.der
   ```

### ❌ Blocked Operations After Sealing

1. **Add new root CA**
   ```bash
   # FAILS - boot_root_certs is sealed
   keyctl padd asymmetric "new_root" @boot_root_certs < new_root.der
   # Error: -EACCES (keyring is restricted)
   ```

2. **Add cert signed by intermediate CA**
   ```bash
   # FAILS - secondary_trusted_keys only accepts certs signed by boot_root_certs
   keyctl padd asymmetric "cert_from_intermediate" @s < cert.der
   # Error: -EKEYREJECTED (not signed by root CA)
   ```

## Implementation Files

### Modified Files

1. **`certs/system_keyring.c`**
   - Added `boot_root_certs` keyring
   - Added `boot_root_certs_add_cert()` function
   - Updated `secondary_trusted_keys_seal()` with two-phase sealing

2. **`include/keys/system_keyring.h`**
   - Exported `boot_root_certs_add_cert()`

3. **`security/boot_certs/boot_certs_sysfs.c`**
   - Added `bc_is_root_ca()` helper to detect self-signed certificates
   - Updated `boot_certs_load_into_secondary_keyring()` to use two-phase loading

### No Kernel Core Modifications Required

This solution uses **only existing kernel keyring infrastructure**:
- `keyring_restrict()` - existing kernel function
- `restrict_link_by_key_or_keyring` - existing restriction function
- `KEY_ALLOC_BYPASS_RESTRICTION` - existing flag for initial population

## Testing

### Verify Setup

```bash
# Check that both keyrings exist
keyctl show @s
# Should see .boot_root_certs and .secondary_trusted_keys

# Check boot_root_certs contents
keyctl list @boot_root_certs
# Should see only root CA certificates

# Check secondary_trusted_keys contents
keyctl list @secondary_trusted_keys
# Should see all certificates (roots + intermediates)
```

### Test Sealing

```bash
# After sealing, try to add a new root CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
    -keyout /tmp/badroot.key -out /tmp/badroot.pem -days 365 -nodes
openssl x509 -in /tmp/badroot.pem -outform DER -out /tmp/badroot.der

keyctl padd asymmetric "bad_root" @boot_root_certs < /tmp/badroot.der
# Should fail with "add_key: Permission denied"

keyctl padd asymmetric "bad_root" @s < /tmp/badroot.der
# Should fail with "add_key: Key was rejected by service"
```

### Test Valid Intermediate Addition

```bash
# Create an intermediate CA signed by an existing root
# (Assuming you have root_ca.key and root_ca.pem from boot chain)

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
    -keyout /tmp/new_int.key -out /tmp/new_int.csr -nodes

openssl x509 -req -in /tmp/new_int.csr -CA root_ca.pem -CAkey root_ca.key \
    -CAcreateserial -out /tmp/new_int.pem -days 365 \
    -extensions v3_ca -extfile <(echo "[v3_ca]
basicConstraints=CA:TRUE
keyUsage=keyCertSign,cRLSign")

openssl x509 -in /tmp/new_int.pem -outform DER -out /tmp/new_int.der

keyctl padd asymmetric "new_intermediate" @s < /tmp/new_int.der
# Should succeed!
```

## Security Properties

### What This Achieves

✅ **Root Certificate Immutability**
- Root CAs in `boot_root_certs` cannot be added, removed, or modified after sealing
- Guarantees that the trust anchor remains stable

✅ **Hierarchical Trust**
- New certificates can only be added if signed by a root CA
- Intermediate CAs cannot sign new certificates for the keyring (though they can sign modules if they're in the chain)

✅ **Runtime Flexibility**
- New intermediate CAs can be added dynamically
- Useful for key rotation without rebooting

### What This Does NOT Protect Against

❌ **Compromised Root CA Private Key**
- If an attacker obtains the private key of a root CA, they can sign arbitrary certificates
- Mitigation: Keep root CA keys offline, use HSMs

❌ **Certificate Expiry**
- Expired certificates will fail validation
- Mitigation: Monitor expiry dates, rotate before expiration

❌ **Revocation**
- This system doesn't implement CRL or OCSP checking
- Mitigation: Could be added via kernel revocation list support

## Comparison with Competitors

Your implementation now solves what "your competitors haven't been able to":

1. **Selective Sealing** - Locks roots while allowing intermediates to be added
2. **No Kernel Core Patches** - Uses existing keyring infrastructure
3. **Clean Separation** - Two keyrings with clear roles
4. **Boot Chain Validation** - Hash pinning + filesystem read-only enforcement
5. **Runtime Flexibility** - Can add new intermediate CAs without reboot

## Future Enhancements

### Potential Improvements

1. **Time-to-Live for Intermediate CAs**
   - Add expiry enforcement for dynamically added intermediates

2. **Audit Logging**
   - Log all certificate additions to boot_root_certs and secondary_trusted_keys

3. **Sysfs Interface for Runtime Addition**
   - Add `/sys/kernel/boot_certs/add_intermediate` for controlled runtime additions

4. **Certificate Revocation**
   - Integrate with kernel's blacklist keyring

5. **Multi-Root Support**
   - Allow multiple independent root CA chains

## References

- [Linux Kernel Keyring Documentation](https://www.kernel.org/doc/html/latest/security/keys/core.html)
- [PKCS#7 Message Verification](https://www.kernel.org/doc/html/latest/crypto/asymmetric-keys.html)
- [Kernel Module Signing](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
