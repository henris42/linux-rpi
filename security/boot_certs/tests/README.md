# Boot Certificate System - Test Suite

Comprehensive test suite for the boot certificate validation system, including certificate generation, expiry enforcement, and hierarchical keyring sealing.

## Features

✅ **Unit Tests**
- Certificate generation and validation
- Expiry detection logic
- Hash calculation
- Policy enforcement logic

✅ **Integration Tests**
- Kernel module sysfs interface
- Keyring structure validation
- Hierarchical sealing verification
- Runtime certificate addition

✅ **Future: EST/REST Integration**
- Certificate signing via EST protocol
- Short-term certificates for expiry testing
- Temporary intermediate CA generation
- Automated certificate rotation

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

### 2. Run Unit Tests (No kernel module required)

```bash
# Run all unit tests
./run_tests.sh

# Or use pytest directly (after activating venv)
source venv/bin/activate
pytest test_boot_certs.py -v
```

**Expected output:**
```
===================== 11 passed, 4 skipped in 0.5s =====================
```

### 3. Run Integration Tests (Requires root + loaded module)

**IMPORTANT:** Integration tests require the NEW kernel module with expiry features. If you're running the old module version, some tests will fail (expiry_status sysfs file won't exist).

```bash
# First, rebuild and load the NEW kernel module
cd /home/hs/linux-rpi
make -j$(nproc)
make modules
cd security/boot_certs
sudo rmmod boot_certs_sysfs  # Remove old module if loaded
sudo insmod boot_certs_sysfs.ko

# Run all tests
cd tests
sudo ./run_tests.sh --all

# Or just kernel integration tests
sudo ./run_tests.sh --kernel
```

**Expected output with NEW module:**
```
===================== 18 passed in 0.8s =====================
```

**Expected output with OLD module:**
```
=========== 2 failed, 14 passed, 7 skipped in 0.8s ===========
```
(Failures: `test_sysfs_interface_exists`, `test_read_expiry_status` - expiry features not in old module)

## Test Structure

```
tests/
├── test_boot_certs.py           # Main test suite
├── est_rest_service_stub.py     # Future EST/REST service
├── run_tests.sh                 # Test runner script
├── requirements.txt             # Python dependencies
├── pytest.ini                   # Pytest configuration
├── README.md                    # This file
└── output/                      # Test artifacts (created during tests)
    ├── valid_root_ca.pem
    ├── test_chain.pem
    └── chain_hash.txt
```

## Test Categories

### Unit Tests (No special privileges required)

**Certificate Generation:**
```bash
pytest test_boot_certs.py::TestCertificateGeneration -v
```
- Test root CA generation
- Test intermediate CA generation
- Test certificate chain creation
- Test expiry date handling

**Expiry Detection:**
```bash
pytest test_boot_certs.py::TestExpiryDetection -v
```
- Test valid certificate detection
- Test expired certificate detection
- Test expiring-soon detection
- Test policy logic (WARN/REJECT/STRICT)

### Integration Tests (Requires root + loaded module)

**Kernel Module:**
```bash
sudo pytest test_boot_certs.py::TestKernelModule -v -m kernel
```
- Sysfs interface availability
- Status reading
- Manual expiry checks
- Keyring structure

**Hierarchical Sealing:**
```bash
sudo pytest test_boot_certs.py::TestHierarchicalSealing -v -m kernel
```
- Block new root CAs
- Block unsigned certificates
- Allow intermediate CAs signed by roots

## Running Specific Tests

```bash
# Run tests by name pattern
pytest test_boot_certs.py -k test_expiry -v

# Run tests by marker
pytest test_boot_certs.py -m kernel -v
pytest test_boot_certs.py -m "not kernel" -v

# Run with coverage
./run_tests.sh --coverage

# Generate HTML coverage report
pytest --cov=. --cov-report=html
# View: firefox htmlcov/index.html
```

## Test Markers

Tests are marked for selective execution:

- `@pytest.mark.kernel` - Requires loaded kernel module
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.est` - Requires EST service (future)
- `@pytest.mark.rest` - Requires REST API (future)

Example: Skip kernel tests
```bash
pytest -m "not kernel" -v
```

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
