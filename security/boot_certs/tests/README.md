# Boot Certificate System - Test Suite

Test suite for the boot certificate validation and module signing system,
covering certificate generation, expiry enforcement, hierarchical keyring
sealing, and both ECC and FALCON-1024 module signing.

## Features

- **Certificate Tests** - Generation, expiry detection, policy logic
- **ECC Module Signing** - Build, sign (sha3-512), load, reject unsigned
- **FALCON Module Signing** - Sign (falcon-1024), load, verify PQC works
- **Kernel Integration** - sysfs interface, keyring structure, sealing
- **EST/REST** - Stubs for future CA service (skipped by default)

## Quick Start

### 1. Install Dependencies (Virtual Environment Required on Raspberry Pi OS)

```bash
cd /home/hs/linux-rpi/security/boot_certs/tests

# Create virtual environment (required on Raspberry Pi OS due to PEP 668)
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Note:** The `run_tests.sh` script automatically activates the virtual environment if it exists.

### 2. Run Tests

```bash
# Unit tests only (no root required)
./run_tests.sh

# All tests including module signing load tests (requires root)
sudo venv/bin/python -m pytest test_boot_certs.py -v

# Signing tests only
sudo pytest test_boot_certs.py -m signing -v

# Kernel integration only
sudo pytest test_boot_certs.py -m kernel -v
```

**Expected output (as root):**
```
28 passed, 6 skipped in 5.5s
```

## Test Structure

```
tests/
├── test_boot_certs.py         # Main test suite (34 tests)
├── pytest.ini                 # Pytest markers and config
├── requirements.txt           # Python dependencies
├── run_tests.sh               # Convenience runner script
├── hello-test/                # Test kernel module
│   ├── hello.c                #   Simple hello_kmod source
│   └── Makefile               #   Build against running kernel
├── module_signing_ecdsa.pem   # ECC private key (PKCS#8)
├── module_signing_ecdsa.x509  # ECC signing certificate (PEM)
├── falcon_private.key         # FALCON-1024 private key
├── falcon.pem                 # FALCON-1024 signing certificate
├── est_rest_service_stub.py   # Future EST/REST service stub
├── output/                    # Generated test artifacts
└── venv/                      # Python virtual environment
```

## Test Categories

### Unit Tests (no root required)

| Class | Tests | What it covers |
|-------|-------|----------------|
| `TestCertificateGeneration` | 5 | Root/intermediate/expired cert creation, SHA3-512 |
| `TestExpiryDetection` | 6 | WARN/REJECT/STRICT policy logic |

### Module Signing Tests (`@pytest.mark.signing`)

| Class | Tests | What it covers |
|-------|-------|----------------|
| `TestECCSigning` | 6 | Build hello.ko, sign sha3-512, load, reject unsigned |
| `TestFalconSigning` | 5 | Sign falcon-1024, load PQC module, size comparison |

Loading tests require root. Signing-only tests work without root.

### Kernel Integration Tests (`@pytest.mark.kernel`)

| Class | Tests | What it covers |
|-------|-------|----------------|
| `TestKernelModule` | 6 | sysfs files, status, expiry, keyrings |
| `TestHierarchicalSealing` | 2 | Block rogue roots, block unsigned certs |

### EST/REST Tests (`@pytest.mark.est`, skipped)

| Class | Tests | What it covers |
|-------|-------|----------------|
| `TestESTRESTIntegration` | 4 | Future CA service (all skipped) |

## Running Specific Tests

```bash
# By marker
pytest -m signing -v                    # All signing tests
pytest -m kernel -v                     # All kernel integration
pytest -m "not kernel" -v               # Skip kernel tests

# By class
pytest test_boot_certs.py::TestFalconSigning -v
pytest test_boot_certs.py::TestECCSigning -v

# By name pattern
pytest -k test_expiry -v
pytest -k "falcon and load" -v

# With coverage
./run_tests.sh --coverage
```

## Test Markers

- `@pytest.mark.signing` - Module signing tests (ECC + FALCON)
- `@pytest.mark.kernel` - Kernel integration (requires boot_certs active)
- `@pytest.mark.est` - EST service tests (skipped, future)

## Test Fixtures

Available fixtures provide test data:

- `valid_root_ca` - Generate valid root CA
- `expired_root_ca` - Generate expired root CA
- `expiring_soon_root_ca` - Generate root CA expiring in 15 days
- `certificate_chain` - Generate complete cert chain (root + intermediate)
- `test_output_dir` - Directory for test artifacts

## Example: Generate Test Certificates

```python
from test_boot_certs import CertificateBuilder

# Generate a valid root CA
root_key, root_cert = CertificateBuilder.create_root_ca("Test Root CA")

# Generate an intermediate
int_key, int_cert = CertificateBuilder.create_intermediate_ca(
    "Test Intermediate CA",
    root_key,
    root_cert
)

# Create chain PEM
chain_pem = (
    CertificateBuilder.cert_to_pem(root_cert) +
    CertificateBuilder.cert_to_pem(int_cert)
)

# Calculate hash for kernel cmdline
hash_hex = CertificateBuilder.calculate_sha3_512(chain_pem)
print(f"boot_certs.sha3={hash_hex}")
```

## Future: EST/REST Service

### Planned Endpoints

**EST Protocol (RFC 7030):**
```
POST /est/simpleenroll         - Certificate enrollment (CSR submission)
POST /est/simplereenroll       - Certificate renewal
GET  /est/cacerts              - Get CA certificate chain
```

**REST API:**
```
POST   /api/v1/certs/sign                      - Sign a CSR
POST   /api/v1/certs/short-term                - Generate short-term cert
POST   /api/v1/certs/temporary-intermediate    - Generate temp intermediate CA
GET    /api/v1/certs/{serial}                  - Get certificate
DELETE /api/v1/certs/{serial}                  - Revoke certificate
```

### Example Usage (Future)

```python
import requests

# Generate short-term cert for expiry testing
response = requests.post(
    'https://ca.example.com/api/v1/certs/short-term',
    json={
        'subject_cn': 'Test Expiring Cert',
        'validity_hours': 2  # Expires in 2 hours
    },
    verify='ca-cert.pem'
)

cert_data = response.json()
# Use cert_data['certificate'] for testing expiry enforcement
```

### Stub Implementation

A basic stub is provided in `est_rest_service_stub.py`:

```python
from est_rest_service_stub import ESTRESTService

# Initialize service with your CA
service = ESTRESTService(ca_cert, ca_key)

# Create short-term certificate
result = service.rest_create_short_term_cert(
    subject_cn="Test Short-term",
    validity_hours=24
)
print(result['expires_at'])

# Create temporary intermediate
result = service.rest_create_temporary_intermediate(
    subject_cn="Temp Intermediate",
    validity_days=30
)
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Boot Certs Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          cd security/boot_certs/tests
          pip install -r requirements.txt
      - name: Run unit tests
        run: |
          cd security/boot_certs/tests
          pytest -m "not kernel" --cov=. --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

## Troubleshooting

### error: externally-managed-environment

**Problem:** Raspberry Pi OS (and modern Debian/Ubuntu) prevents system-wide pip installations due to PEP 668.

**Solution:** Use a virtual environment (recommended):
```bash
cd /home/hs/linux-rpi/security/boot_certs/tests
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# The run_tests.sh script will automatically activate venv if it exists
./run_tests.sh
```

**Alternative:** Use `--break-system-packages` (not recommended):
```bash
pip3 install -r requirements.txt --break-system-packages
```

### ModuleNotFoundError: No module named 'cryptography'

Install dependencies (use venv on Raspberry Pi OS):
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### pytest: command not found

The pytest command is only available after installing dependencies:
```bash
source venv/bin/activate  # If using venv
pip install -r requirements.txt
```

Or run with Python module syntax:
```bash
python3 -m pytest test_boot_certs.py -v
```

### PermissionError when running kernel tests

Kernel integration tests require root:
```bash
sudo ./run_tests.sh --all
```

**Note:** The script will activate the venv automatically.

### Module not loaded error

Load the boot_certs module first:
```bash
cd /home/hs/linux-rpi/security/boot_certs
sudo insmod boot_certs_sysfs.ko

# Verify it's loaded
lsmod | grep boot_certs
cat /sys/kernel/boot_certs/ok
```

### Tests fail: expiry_status file not found

**Problem:** Running tests with OLD kernel module (before expiry features).

**Solution:** Rebuild and reload the NEW module:
```bash
cd /home/hs/linux-rpi
make -j$(nproc) modules
cd security/boot_certs
sudo rmmod boot_certs_sysfs  # Remove old module
sudo insmod boot_certs_sysfs.ko  # Load new module
cd tests
sudo ./run_tests.sh --all
```

**Expected failures with OLD module:**
- `test_sysfs_interface_exists` - expiry_status file doesn't exist
- `test_read_expiry_status` - can't read non-existent file

All other tests should pass with the old module.

## Contributing

When adding new tests:

1. **Follow naming convention**: `test_<feature>_<scenario>()`
2. **Use appropriate markers**: `@pytest.mark.kernel`, etc.
3. **Add docstrings**: Explain what the test validates
4. **Use fixtures**: Avoid duplicating test data generation
5. **Keep tests isolated**: Each test should be independent

Example:
```python
@pytest.mark.kernel
@pytest.mark.skipif(os.geteuid() != 0, reason="Requires root")
def test_add_intermediate_ca(self, certificate_chain):
    """Test adding intermediate CA signed by boot root"""
    # Test implementation...
    pass
```

## References

- [pytest Documentation](https://docs.pytest.org/)
- [cryptography Library](https://cryptography.io/)
- [RFC 7030: EST Protocol](https://datatracker.ietf.org/doc/html/rfc7030)
- [Boot Certificate Documentation](../IMPLEMENTATION_COMPLETE.md)

## License

GPL-2.0 - See kernel module license
