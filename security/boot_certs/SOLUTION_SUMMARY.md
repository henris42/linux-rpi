# Boot Certificate & PQC Module Signing - Solution Summary

## Overview

A **hierarchical two-keyring PKI system** with support for both classical (ECC)
and post-quantum (FALCON-1024) kernel module signing:

- Root certificates locked and immutable after boot
- New intermediate CAs can be added if signed by a root
- Kernel modules verified with ECDSA or FALCON-1024 signatures
- PKCS#7 signature validation through the standard kernel infrastructure

## Certificate Trust Hierarchy

```mermaid
graph TD
    subgraph "Boot Firmware (/boot/firmware/certs/chain.pem)"
        ECC_ROOT["Storax Root ECC 01<br/><i>Self-signed, ECC P-384</i>"]
        ECC_INT["Storax Device ECC 01<br/><i>Intermediate</i>"]
        FALCON_ROOT["NTS Falcon Root 01<br/><i>Self-signed, FALCON-1024</i>"]
        FALCON_INT["NTS Falcon Issuing 02<br/><i>Intermediate</i>"]

        ECC_ROOT -->|signs| ECC_INT
        FALCON_ROOT -->|signs| FALCON_INT
    end

    subgraph "Kernel Keyrings"
        BOOT_ROOT[".boot_root_certs<br/><b>SEALED</b>"]
        SECONDARY[".secondary_trusted_keys<br/><i>Module verification</i>"]
    end

    ECC_ROOT --> BOOT_ROOT
    FALCON_ROOT --> BOOT_ROOT
    ECC_ROOT --> SECONDARY
    FALCON_ROOT --> SECONDARY
    ECC_INT --> SECONDARY
    FALCON_INT --> SECONDARY

    BOOT_ROOT -.->|restricts| SECONDARY

    style BOOT_ROOT fill:#d32f2f,color:#fff
    style SECONDARY fill:#1565c0,color:#fff
    style ECC_ROOT fill:#2e7d32,color:#fff
    style FALCON_ROOT fill:#6a1b9a,color:#fff
```

## Boot Sequence

```mermaid
sequenceDiagram
    participant FW as Boot Firmware
    participant BC as boot_certs
    participant KR as Keyrings
    participant KM as Kernel Modules

    FW->>BC: chain.pem available
    BC->>BC: Verify SHA3-512 hash<br/>(pinned in cmdline)
    BC->>BC: Parse PEM → 4 DER certs
    BC->>BC: Identify root CAs<br/>(subject == issuer)

    Note over BC,KR: Phase 1: Root CAs
    BC->>KR: Add ECC root → .boot_root_certs
    BC->>KR: Add ECC root → .secondary_trusted_keys
    BC->>KR: Add FALCON root → .boot_root_certs
    BC->>KR: Add FALCON root → .secondary_trusted_keys

    Note over BC,KR: Phase 2: Intermediates
    BC->>KR: Add ECC intermediate → .secondary_trusted_keys
    BC->>KR: Add FALCON intermediate → .secondary_trusted_keys

    Note over KR: Phase 3: Seal
    KR->>KR: Seal .boot_root_certs<br/>(no new keys allowed)
    KR->>KR: Restrict .secondary_trusted_keys<br/>(only root-signed certs)

    Note over KR,KM: Runtime
    KM->>KR: insmod signed.ko
    KR->>KR: Verify PKCS#7 signature<br/>against .secondary_trusted_keys
    KR-->>KM: OK / EKEYREJECTED
```

## Module Signing Flow

```mermaid
flowchart LR
    subgraph "Build Host"
        SRC["module.c"] --> KO["module.ko<br/><i>unsigned</i>"]
        KO --> SF["sign-file"]
        KEY["Private Key<br/><i>ECC or FALCON</i>"] --> SF
        CERT["Certificate<br/><i>.x509 or .pem</i>"] --> SF
        SF --> SIGNED["module.ko<br/><i>+ PKCS#7 sig</i>"]
    end

    subgraph "Target Device (Kernel)"
        SIGNED --> INSMOD["insmod"]
        INSMOD --> PKCS7["PKCS#7 Parser"]
        PKCS7 --> VERIFY{"Signature<br/>Algorithm?"}
        VERIFY -->|ECDSA| ECDSA_V["ECDSA verify<br/><i>SHA3-512 digest</i>"]
        VERIFY -->|FALCON| FALCON_V["FALCON verify<br/><i>raw TBS, SHAKE256</i>"]
        ECDSA_V --> TRUST["Trust<br/>Validation"]
        FALCON_V --> TRUST
        TRUST --> KEYS[".secondary_trusted_keys"]
        KEYS -->|found| OK["Module loaded"]
        KEYS -->|not found| REJECT["EKEYREJECTED"]
    end

    style SIGNED fill:#1565c0,color:#fff
    style OK fill:#2e7d32,color:#fff
    style REJECT fill:#d32f2f,color:#fff
```

## FALCON-1024 Verification Pipeline

```mermaid
flowchart TD
    INPUT["Signed Data<br/><i>sig || TBS certificate</i>"]

    INPUT --> HEADER["Parse header byte<br/><i>0x3a = FALCON-1024</i>"]
    HEADER --> NONCE["Extract nonce<br/><i>40 bytes</i>"]
    HEADER --> COMP["Compressed signature<br/><i>comp_decode → s2 polynomial</i>"]

    INPUT --> PUBKEY["Public key<br/><i>modq_decode → h polynomial</i>"]
    PUBKEY --> NTT_H["to_ntt_monty(h)<br/><i>NTT + Montgomery form</i>"]

    NONCE --> SHAKE["SHAKE256(nonce || TBS)"]
    SHAKE --> H2P["hash_to_point_ct<br/><i>→ c0 polynomial (mod q)</i>"]

    COMP --> RED["Reduce s2 mod q"]
    RED --> NTT_S2["NTT(s2)"]
    NTT_S2 --> MUL["s2 * h<br/><i>Montgomery multiply</i>"]
    NTT_H --> MUL
    MUL --> INTT["iNTT"]
    INTT --> SUB["s1 = s2*h - c0"]
    H2P --> SUB
    SUB --> NORM["||s1, s2||² ≤ bound?"]
    NORM -->|Yes| VALID["Signature Valid"]
    NORM -->|No| INVALID["Signature Invalid"]

    style SHAKE fill:#6a1b9a,color:#fff
    style VALID fill:#2e7d32,color:#fff
    style INVALID fill:#d32f2f,color:#fff
```

## Keyring Security Model

```mermaid
flowchart TD
    subgraph "Immutable Trust Anchor"
        BRC[".boot_root_certs<br/><b>SEALED at boot</b>"]
    end

    subgraph "Runtime Trust Store"
        STK[".secondary_trusted_keys"]
    end

    ROOT_ADD["Add new root CA"] -->|BLOCKED| BRC
    ROGUE["Add rogue cert<br/><i>not signed by root</i>"] -->|BLOCKED| STK
    INTER["Add intermediate CA<br/><i>signed by boot root</i>"] -->|ALLOWED| STK

    STK --> MODSIG["Module signature<br/>verification"]

    BRC -.->|"restrict_link_by_key_or_keyring<br/>(NOT _chain)"| STK

    style BRC fill:#d32f2f,color:#fff
    style STK fill:#1565c0,color:#fff
    style ROOT_ADD fill:#616161,color:#fff
    style ROGUE fill:#616161,color:#fff
    style INTER fill:#2e7d32,color:#fff
```

## Key Components

### Kernel Crypto: FALCON-1024 Verification (`crypto/falcon/`)

| File | Purpose |
|------|---------|
| `falcon_verify.c` | Kernel crypto API integration (akcipher interface) |
| `pqclean_verify.c` | PQClean FALCON verification wrapper |
| `vrfy.c` | NTT, Montgomery arithmetic, verify_raw |
| `common.c` | hash_to_point, is_short norm check |
| `codec.c` | Signature/public key encoding/decoding |
| `shake256_kernel.h` | SHAKE256 using kernel's Keccak permutation |
| `inner.h` | Internal API mapping PQClean to kernel |

### Module Signing (`scripts/sign-file.c`)

Extended to support PQC signatures:
- Detects FALCON keys via oqs-provider
- Constructs PKCS#7 SignedData with FALCON OIDs (1.3.9999.3.9)
- Uses SHA3-512 as the placeholder digest algorithm
- Signs raw module data via EVP_DigestSign (FALCON handles hashing internally)

### X.509 Certificate Parsing (`crypto/asymmetric_keys/`)

| File | Changes |
|------|---------|
| `x509_cert_parser.c` | Strip BIT STRING unused-bits for FALCON sig/pubkey |
| `x509_public_key.c` | Raw TBS as digest when hash_algo=NULL (FALCON) |
| `pkcs7_parser.c` | Recognize FALCON OIDs, set pkey_algo="falcon-1024" |

### Boot Certificate Loader (`security/boot_certs/`)

| File | Purpose |
|------|---------|
| `boot_certs_sysfs.c` | Loads chain.pem, parses certs, populates keyrings |
| `boot_certs_crl.c` | Certificate revocation list support |

### OID Registry (`include/linux/oid_registry.h`)

Added FALCON-512 (1.3.9999.3.6) and FALCON-1024 (1.3.9999.3.9) OIDs.

## Critical Bugs Fixed

### 1. SHAKE256 Squeeze Block Boundary Bug

**File:** `crypto/falcon/shake256_kernel.h`

The squeeze function never permuted the Keccak state when small extraction
calls (2 bytes) aligned exactly with the 136-byte block boundary. After 68
calls consumed one full block, subsequent reads returned **the same block**
instead of fresh output.

**Impact:** hash_to_point_ct produced correct output for only the first 68
of 1024 polynomial elements. The remaining 956 elements were wrong, making
the computed s1 effectively random and the norm check overflow.

**Fix:** Check for block boundary at the start of each iteration:
```c
if (offset == 0 && sc->squeezed > 0)
    crypto_sha3_permute(sc->state.st);
```

### 2. Scatterlist Data Extraction Bug

**File:** `crypto/falcon/falcon_verify.c`

The verify function read the message from `req->dst` (which is NULL for
verify operations). The kernel's akcipher verify API places both signature
and message concatenated in `req->src`.

**Fix:** Use `sg_pcopy_to_buffer(req->src, ..., total_len, 0)` to read
the combined [signature || message] buffer from req->src.

### 3. Boot Cert Root CA Count

**File:** `security/boot_certs/boot_certs_sysfs.c`

The summary log used a hardcoded estimate instead of the actual root CA count.
Fixed to iterate and count self-signed certificates.

## Building

```bash
# Prerequisites: oqs-provider for OpenSSL (FALCON key generation/signing)
# See: https://github.com/open-quantum-safe/oqs-provider

cd /home/hs/linux-rpi

# Build kernel + modules
make -j$(nproc) Image.gz modules

# Install
sudo mount -o remount,rw /boot/firmware
sudo cp arch/arm64/boot/Image.gz /boot/firmware/kernel8.img
sudo make modules_install
```

## Signing Kernel Modules

### ECC (ECDSA with SHA3-512)
```bash
scripts/sign-file sha3-512 <private_key.pem> <certificate.x509> module.ko
```

### FALCON-1024 (Post-Quantum)
```bash
scripts/sign-file falcon-1024 <falcon_private.key> <falcon_cert.pem> module.ko
```

## Verification

```bash
# Check boot_certs loaded
cat /sys/kernel/boot_certs/ok          # true
cat /sys/kernel/boot_certs/status      # detailed status

# Check keyrings
sudo keyctl list @boot_root_certs      # root CAs
sudo keyctl list @s                    # all trusted keys

# Test module loading
sudo insmod hello.ko                   # signed module loads
sudo insmod unsigned.ko                # rejected: EKEYREJECTED
```

## Test Suite

```bash
cd security/boot_certs/tests
source venv/bin/activate
sudo pytest test_boot_certs.py -v      # 28 passed, 6 skipped
```

| Category | Tests | Description |
|----------|-------|-------------|
| Certificate Generation | 5 | Create root/intermediate/expired certs |
| Expiry Detection | 6 | WARN/REJECT/STRICT policy logic |
| ECC Signing | 6 | Build, sign, load, reject unsigned |
| FALCON Signing | 5 | Sign, load, verify PQC signatures |
| Kernel Integration | 6 | sysfs, keyrings, expiry checks |
| Hierarchical Sealing | 2 | Block rogue roots (requires sealed) |
| EST/REST | 4 | Skipped (future) |

## Security Model

| Scenario | Prevented? | How |
|----------|-----------|-----|
| Add rogue root CA | Yes | boot_root_certs is sealed |
| Add cert signed by intermediate | Yes | secondary restricted to root-signed only |
| Add cert signed by boot root | Allowed | Intended use case |
| Replace boot chain.pem | Yes | SHA3-512 hash pinning + RO filesystem |
| Load unsigned module | Yes | MODULE_SIG_FORCE rejects |
| Load wrong-key-signed module | Yes | PKCS#7 trust validation fails |

## Boot Parameters

```
boot_certs.sha3=<128 hex chars of SHA3-512 hash of chain.pem>
```
