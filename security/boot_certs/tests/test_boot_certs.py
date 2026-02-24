#!/usr/bin/env python3
"""
Boot Certificate System - Test Suite

Tests hierarchical keyring sealing, certificate expiry enforcement,
module signing (ECC + FALCON), and runtime certificate management.

Requirements:
    pip install pytest cryptography python-dateutil

Usage:
    pytest test_boot_certs.py -v                          # Unit tests only
    pytest test_boot_certs.py -v -m signing               # Module signing tests
    sudo pytest test_boot_certs.py -v -m kernel           # Kernel integration
    sudo pytest test_boot_certs.py -v --run-est           # Include EST tests
"""

import os
import shutil
import subprocess
import tempfile
import hashlib
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Tuple, List

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


# ============================================================================
# Test Configuration
# ============================================================================

class Config:
    """Test configuration"""
    # Paths
    BOOT_CERTS_SYSFS = Path("/sys/kernel/boot_certs")
    BOOT_FIRMWARE = Path("/boot/firmware")
    CHAIN_PEM_PATH = BOOT_FIRMWARE / "certs" / "chain.pem"

    # Keyring names
    BOOT_ROOT_KEYRING = "@boot_root_certs"
    SECONDARY_KEYRING = "@s"

    # Test data
    TEST_DIR = Path(__file__).parent
    TEST_OUTPUT = TEST_DIR / "output"
    HELLO_DIR = TEST_DIR / "hello-test"
    KERNEL_SRC = Path("/home/hs/linux-rpi")

    # Signing tools and keys
    SIGN_FILE = KERNEL_SRC / "scripts" / "sign-file"

    # ECC signing keys
    ECC_PRIVATE_KEY = TEST_DIR / "module_signing_ecdsa.pem"
    ECC_CERTIFICATE = TEST_DIR / "module_signing_ecdsa.x509"

    # FALCON signing keys
    FALCON_PRIVATE_KEY = TEST_DIR / "falcon_private.key"
    FALCON_CERTIFICATE = TEST_DIR / "falcon.pem"

    # Certificate validity periods
    ROOT_CA_VALIDITY_DAYS = 3650   # 10 years
    INTERMEDIATE_VALIDITY_DAYS = 1825  # 5 years
    LEAF_VALIDITY_DAYS = 365  # 1 year


# ============================================================================
# Certificate Generation Helpers
# ============================================================================

class CertificateBuilder:
    """Helper class for generating test certificates"""

    @staticmethod
    def generate_private_key() -> ec.EllipticCurvePrivateKey:
        """Generate ECC private key (secp384r1)"""
        return ec.generate_private_key(ec.SECP384R1(), default_backend())

    @staticmethod
    def create_root_ca(
        subject_name: str,
        validity_days: int = Config.ROOT_CA_VALIDITY_DAYS,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None
    ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        """Create a self-signed root CA certificate"""
        private_key = CertificateBuilder.generate_private_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])

        now = datetime.utcnow()
        not_before = not_valid_before or now
        not_after = not_valid_after or (now + timedelta(days=validity_days))

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        return private_key, cert

    @staticmethod
    def create_intermediate_ca(
        subject_name: str,
        issuer_key: ec.EllipticCurvePrivateKey,
        issuer_cert: x509.Certificate,
        validity_days: int = Config.INTERMEDIATE_VALIDITY_DAYS,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None
    ) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        """Create an intermediate CA certificate signed by issuer"""
        private_key = CertificateBuilder.generate_private_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])

        now = datetime.utcnow()
        not_before = not_valid_before or now
        not_after = not_valid_after or (now + timedelta(days=validity_days))

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False,
            )
            .sign(issuer_key, hashes.SHA256(), default_backend())
        )

        return private_key, cert

    @staticmethod
    def cert_to_pem(cert: x509.Certificate) -> bytes:
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def cert_to_der(cert: x509.Certificate) -> bytes:
        return cert.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def calculate_sha3_512(data: bytes) -> str:
        return hashlib.sha3_512(data).hexdigest()


# ============================================================================
# System Interaction Helpers
# ============================================================================

class SystemHelper:
    """Helper for interacting with the kernel module and keyrings"""

    @staticmethod
    def is_module_loaded() -> bool:
        """Check if boot_certs is active (built-in or module)"""
        return Config.BOOT_CERTS_SYSFS.exists()

    @staticmethod
    def read_sysfs_file(filename: str) -> Optional[str]:
        path = Config.BOOT_CERTS_SYSFS / filename
        try:
            return path.read_text().strip()
        except Exception:
            return None

    @staticmethod
    def write_sysfs_file(filename: str, value: str) -> bool:
        path = Config.BOOT_CERTS_SYSFS / filename
        try:
            path.write_text(value)
            return True
        except Exception:
            return False

    @staticmethod
    def get_keyring_keys(keyring: str) -> List[str]:
        try:
            result = subprocess.run(
                ["keyctl", "list", keyring],
                capture_output=True, text=True, check=True
            )
            keys = []
            for line in result.stdout.split('\n'):
                if 'asymmetric:' in line:
                    desc = line.split('asymmetric:')[1].strip()
                    keys.append(desc)
            return keys
        except subprocess.CalledProcessError:
            return []

    @staticmethod
    def add_key_to_keyring(keyring: str, desc: str, der_data: bytes) -> bool:
        try:
            with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
                f.write(der_data)
                temp_path = f.name
            try:
                subprocess.run(
                    ["keyctl", "padd", "asymmetric", desc, keyring],
                    stdin=open(temp_path, 'rb'),
                    capture_output=True, check=True
                )
                return True
            finally:
                os.unlink(temp_path)
        except subprocess.CalledProcessError:
            return False


# ============================================================================
# Module Signing Helper
# ============================================================================

class ModuleSignHelper:
    """Helper for building, signing, and loading kernel modules"""

    @staticmethod
    def build_hello_module() -> Path:
        """Build hello.ko from source, return path to unsigned .ko"""
        hello_dir = Config.HELLO_DIR
        assert hello_dir.exists(), f"hello-test dir not found: {hello_dir}"
        assert (hello_dir / "hello.c").exists(), "hello.c not found"

        # Clean and rebuild
        subprocess.run(
            ["make", "-C", str(Config.KERNEL_SRC),
             f"M={hello_dir}", "clean"],
            capture_output=True, check=True
        )
        result = subprocess.run(
            ["make", "-C", str(Config.KERNEL_SRC),
             f"M={hello_dir}", "modules"],
            capture_output=True, text=True
        )
        ko_path = hello_dir / "hello.ko"
        assert ko_path.exists(), f"Build failed: {result.stderr}"
        return ko_path

    @staticmethod
    def sign_module(ko_path: Path, hash_algo: str,
                    key_path: Path, cert_path: Path,
                    dest: Optional[Path] = None) -> Path:
        """Sign a .ko file, return path to signed module"""
        assert Config.SIGN_FILE.exists(), f"sign-file not found: {Config.SIGN_FILE}"
        assert key_path.exists(), f"Private key not found: {key_path}"
        assert cert_path.exists(), f"Certificate not found: {cert_path}"

        if dest:
            shutil.copy2(ko_path, dest)
            target = dest
        else:
            target = ko_path

        result = subprocess.run(
            [str(Config.SIGN_FILE), hash_algo,
             str(key_path), str(cert_path), str(target)],
            capture_output=True, text=True
        )
        assert result.returncode == 0, \
            f"sign-file failed: {result.stderr}"
        return target

    @staticmethod
    def module_has_signature(ko_path: Path) -> bool:
        """Check if a .ko file has an appended signature"""
        data = ko_path.read_bytes()
        return data.endswith(b"~Module signature appended~\n")

    @staticmethod
    def get_module_sig_info(ko_path: Path) -> dict:
        """Get signature info from modinfo"""
        result = subprocess.run(
            ["modinfo", str(ko_path)],
            capture_output=True, text=True
        )
        info = {}
        for line in result.stdout.splitlines():
            if ':' in line:
                key, _, val = line.partition(':')
                info[key.strip()] = val.strip()
        return info

    @staticmethod
    def load_module(ko_path: Path) -> Tuple[bool, str]:
        """Load a kernel module, return (success, output)"""
        result = subprocess.run(
            ["sudo", "insmod", str(ko_path)],
            capture_output=True, text=True
        )
        return result.returncode == 0, result.stderr.strip()

    @staticmethod
    def unload_module(name: str = "hello") -> bool:
        """Unload a kernel module"""
        result = subprocess.run(
            ["sudo", "rmmod", name],
            capture_output=True, text=True
        )
        return result.returncode == 0

    @staticmethod
    def module_is_loaded(name: str = "hello") -> bool:
        """Check if a module is currently loaded"""
        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True
        )
        return name in result.stdout


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def test_output_dir():
    Config.TEST_OUTPUT.mkdir(parents=True, exist_ok=True)
    return Config.TEST_OUTPUT


@pytest.fixture
def valid_root_ca():
    key, cert = CertificateBuilder.create_root_ca("Test Root CA")
    return key, cert


@pytest.fixture
def expired_root_ca():
    now = datetime.utcnow()
    key, cert = CertificateBuilder.create_root_ca(
        "Expired Root CA",
        not_valid_before=now - timedelta(days=400),
        not_valid_after=now - timedelta(days=1)
    )
    return key, cert


@pytest.fixture
def expiring_soon_root_ca():
    now = datetime.utcnow()
    key, cert = CertificateBuilder.create_root_ca(
        "Expiring Soon Root CA",
        not_valid_before=now - timedelta(days=365),
        not_valid_after=now + timedelta(days=15)
    )
    return key, cert


@pytest.fixture
def certificate_chain(valid_root_ca):
    root_key, root_cert = valid_root_ca
    int_key, int_cert = CertificateBuilder.create_intermediate_ca(
        "Test Intermediate CA", root_key, root_cert
    )
    return {
        'root_key': root_key, 'root_cert': root_cert,
        'intermediate_key': int_key, 'intermediate_cert': int_cert
    }


@pytest.fixture(scope="session")
def unsigned_hello_ko():
    """Build an unsigned hello.ko (once per session)"""
    return ModuleSignHelper.build_hello_module()


# ============================================================================
# Unit Tests - Certificate Generation
# ============================================================================

class TestCertificateGeneration:
    """Test certificate generation helpers"""

    def test_generate_valid_root_ca(self, valid_root_ca, test_output_dir):
        key, cert = valid_root_ca
        assert cert.subject == cert.issuer
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value
        assert bc.ca is True
        now = datetime.utcnow()
        assert cert.not_valid_before <= now
        assert cert.not_valid_after > now
        (test_output_dir / "valid_root_ca.pem").write_bytes(
            CertificateBuilder.cert_to_pem(cert))

    def test_generate_expired_root_ca(self, expired_root_ca):
        key, cert = expired_root_ca
        assert cert.not_valid_after < datetime.utcnow()
        assert cert.subject == cert.issuer

    def test_generate_expiring_soon_root_ca(self, expiring_soon_root_ca):
        key, cert = expiring_soon_root_ca
        days_until_expiry = (cert.not_valid_after - datetime.utcnow()).days
        assert 10 <= days_until_expiry <= 20

    def test_generate_certificate_chain(self, certificate_chain, test_output_dir):
        root_cert = certificate_chain['root_cert']
        int_cert = certificate_chain['intermediate_cert']
        assert int_cert.issuer == root_cert.subject
        chain_pem = (
            CertificateBuilder.cert_to_pem(root_cert) +
            CertificateBuilder.cert_to_pem(int_cert)
        )
        (test_output_dir / "test_chain.pem").write_bytes(chain_pem)

    def test_sha3_512_hash(self, certificate_chain, test_output_dir):
        root_cert = certificate_chain['root_cert']
        int_cert = certificate_chain['intermediate_cert']
        chain_pem = (
            CertificateBuilder.cert_to_pem(root_cert) +
            CertificateBuilder.cert_to_pem(int_cert)
        )
        hash_hex = CertificateBuilder.calculate_sha3_512(chain_pem)
        assert len(hash_hex) == 128
        assert all(c in '0123456789abcdef' for c in hash_hex)
        (test_output_dir / "chain_hash.txt").write_text(hash_hex)


# ============================================================================
# Unit Tests - Expiry Detection
# ============================================================================

class TestExpiryDetection:
    """Test certificate expiry detection logic"""

    def test_detect_valid_certificate(self, valid_root_ca):
        key, cert = valid_root_ca
        now = datetime.utcnow()
        assert cert.not_valid_before <= now
        assert cert.not_valid_after > now

    def test_detect_expired_certificate(self, expired_root_ca):
        key, cert = expired_root_ca
        assert cert.not_valid_after < datetime.utcnow()

    def test_detect_expiring_soon(self, expiring_soon_root_ca):
        key, cert = expiring_soon_root_ca
        days = (cert.not_valid_after - datetime.utcnow()).days
        assert 0 < days < 30

    def test_expiry_policy_warn(self, expired_root_ca):
        key, cert = expired_root_ca
        is_expired = cert.not_valid_after < datetime.utcnow()
        should_reject = False  # WARN mode: log but don't reject
        assert is_expired and not should_reject

    def test_expiry_policy_reject(self, expired_root_ca):
        key, cert = expired_root_ca
        is_expired = cert.not_valid_after < datetime.utcnow()
        should_reject = is_expired
        assert should_reject

    def test_expiry_policy_strict(self, expiring_soon_root_ca):
        key, cert = expiring_soon_root_ca
        days = (cert.not_valid_after - datetime.utcnow()).days
        is_expiring_soon = days < 30
        should_reject = is_expiring_soon
        assert should_reject and is_expiring_soon


# ============================================================================
# Module Signing Tests - ECC
# ============================================================================

@pytest.mark.signing
class TestECCSigning:
    """Test ECC (ECDSA) module signing with sign-file"""

    def test_sign_file_exists(self):
        """sign-file binary exists and is executable"""
        assert Config.SIGN_FILE.exists()
        assert os.access(Config.SIGN_FILE, os.X_OK)

    def test_ecc_key_exists(self):
        """ECC private key and certificate exist"""
        assert Config.ECC_PRIVATE_KEY.exists(), \
            f"ECC key not found: {Config.ECC_PRIVATE_KEY}"
        assert Config.ECC_CERTIFICATE.exists(), \
            f"ECC cert not found: {Config.ECC_CERTIFICATE}"

    def test_build_hello_module(self, unsigned_hello_ko):
        """hello.ko builds successfully"""
        assert unsigned_hello_ko.exists()
        assert unsigned_hello_ko.stat().st_size > 0

    def test_sign_with_ecc(self, unsigned_hello_ko, test_output_dir):
        """Sign hello.ko with ECC key using sha3-512"""
        signed = test_output_dir / "hello_ecc.ko"
        ModuleSignHelper.sign_module(
            unsigned_hello_ko, "sha3-512",
            Config.ECC_PRIVATE_KEY, Config.ECC_CERTIFICATE,
            dest=signed
        )
        assert ModuleSignHelper.module_has_signature(signed)
        # Signed module should be larger than unsigned
        assert signed.stat().st_size > unsigned_hello_ko.stat().st_size

    @pytest.mark.skipif(os.geteuid() != 0, reason="Requires root")
    def test_load_ecc_signed_module(self, unsigned_hello_ko, test_output_dir):
        """Load ECC-signed module into running kernel"""
        # Ensure not already loaded
        ModuleSignHelper.unload_module()

        signed = test_output_dir / "hello_ecc_load.ko"
        ModuleSignHelper.sign_module(
            unsigned_hello_ko, "sha3-512",
            Config.ECC_PRIVATE_KEY, Config.ECC_CERTIFICATE,
            dest=signed
        )

        ok, err = ModuleSignHelper.load_module(signed)
        try:
            assert ok, f"Failed to load ECC-signed module: {err}"
            assert ModuleSignHelper.module_is_loaded("hello")
        finally:
            ModuleSignHelper.unload_module()

    @pytest.mark.skipif(os.geteuid() != 0, reason="Requires root")
    def test_reject_unsigned_module(self, unsigned_hello_ko):
        """Unsigned module is rejected by the kernel"""
        ModuleSignHelper.unload_module()

        ok, err = ModuleSignHelper.load_module(unsigned_hello_ko)
        assert not ok, "Unsigned module should have been rejected"
        assert "Key was rejected" in err or "required key not available" in err


# ============================================================================
# Module Signing Tests - FALCON (Post-Quantum)
# ============================================================================

@pytest.mark.signing
class TestFalconSigning:
    """Test FALCON-1024 post-quantum module signing"""

    def test_falcon_key_exists(self):
        """FALCON private key and certificate exist"""
        assert Config.FALCON_PRIVATE_KEY.exists(), \
            f"FALCON key not found: {Config.FALCON_PRIVATE_KEY}"
        assert Config.FALCON_CERTIFICATE.exists(), \
            f"FALCON cert not found: {Config.FALCON_CERTIFICATE}"

    def test_falcon_cert_is_falcon1024(self):
        """FALCON certificate uses falcon1024 algorithm"""
        result = subprocess.run(
            ["openssl", "x509", "-in", str(Config.FALCON_CERTIFICATE),
             "-noout", "-text"],
            capture_output=True, text=True
        )
        assert "falcon1024" in result.stdout.lower(), \
            "Certificate is not FALCON-1024"

    def test_sign_with_falcon(self, unsigned_hello_ko, test_output_dir):
        """Sign hello.ko with FALCON-1024 key"""
        signed = test_output_dir / "hello_falcon.ko"
        ModuleSignHelper.sign_module(
            unsigned_hello_ko, "falcon-1024",
            Config.FALCON_PRIVATE_KEY, Config.FALCON_CERTIFICATE,
            dest=signed
        )
        assert ModuleSignHelper.module_has_signature(signed)
        assert signed.stat().st_size > unsigned_hello_ko.stat().st_size

    @pytest.mark.skipif(os.geteuid() != 0, reason="Requires root")
    def test_load_falcon_signed_module(self, unsigned_hello_ko, test_output_dir):
        """Load FALCON-signed module into running kernel"""
        ModuleSignHelper.unload_module()

        signed = test_output_dir / "hello_falcon_load.ko"
        ModuleSignHelper.sign_module(
            unsigned_hello_ko, "falcon-1024",
            Config.FALCON_PRIVATE_KEY, Config.FALCON_CERTIFICATE,
            dest=signed
        )

        ok, err = ModuleSignHelper.load_module(signed)
        try:
            assert ok, f"Failed to load FALCON-signed module: {err}"
            assert ModuleSignHelper.module_is_loaded("hello")
        finally:
            ModuleSignHelper.unload_module()

    def test_falcon_signature_larger_than_ecc(self, unsigned_hello_ko,
                                              test_output_dir):
        """FALCON signature is larger than ECC signature"""
        ecc_ko = test_output_dir / "hello_ecc_size.ko"
        falcon_ko = test_output_dir / "hello_falcon_size.ko"

        ModuleSignHelper.sign_module(
            unsigned_hello_ko, "sha3-512",
            Config.ECC_PRIVATE_KEY, Config.ECC_CERTIFICATE,
            dest=ecc_ko
        )
        ModuleSignHelper.sign_module(
            unsigned_hello_ko, "falcon-1024",
            Config.FALCON_PRIVATE_KEY, Config.FALCON_CERTIFICATE,
            dest=falcon_ko
        )

        ecc_overhead = ecc_ko.stat().st_size - unsigned_hello_ko.stat().st_size
        falcon_overhead = falcon_ko.stat().st_size - unsigned_hello_ko.stat().st_size

        # FALCON-1024 sigs are ~1200-1400 bytes; ECC sigs ~100-200 bytes
        assert falcon_overhead > ecc_overhead, \
            f"FALCON overhead ({falcon_overhead}) should exceed " \
            f"ECC overhead ({ecc_overhead})"


# ============================================================================
# Integration Tests - Kernel Module
# ============================================================================

@pytest.mark.kernel
class TestKernelModule:
    """Integration tests requiring loaded boot_certs"""

    @pytest.fixture(autouse=True)
    def check_module_loaded(self):
        if not SystemHelper.is_module_loaded():
            pytest.skip("boot_certs not active")

    def test_sysfs_interface_exists(self):
        assert Config.BOOT_CERTS_SYSFS.exists()
        assert (Config.BOOT_CERTS_SYSFS / "ok").exists()
        assert (Config.BOOT_CERTS_SYSFS / "status").exists()
        assert (Config.BOOT_CERTS_SYSFS / "sealed").exists()
        assert (Config.BOOT_CERTS_SYSFS / "expiry_status").exists()

    def test_read_ok_status(self):
        ok_status = SystemHelper.read_sysfs_file("ok")
        assert ok_status in ["true", "false"]

    def test_read_sealed_status(self):
        sealed = SystemHelper.read_sysfs_file("sealed")
        assert sealed in ["true", "false"]

    def test_read_expiry_status(self):
        expiry_status = SystemHelper.read_sysfs_file("expiry_status")
        assert expiry_status is not None
        parts = dict(item.split('=') for item in expiry_status.split())
        assert 'policy' in parts
        assert 'grace_days' in parts
        assert 'expired' in parts
        assert parts['policy'] in ['WARN', 'REJECT', 'STRICT']

    def test_manual_expiry_check(self):
        path = Config.BOOT_CERTS_SYSFS / "expiry_check_now"
        if not path.exists() or not os.access(path, os.W_OK):
            pytest.skip("No write access to expiry_check_now")
        result = SystemHelper.write_sysfs_file("expiry_check_now", "1")
        assert result

    @pytest.mark.skipif(os.geteuid() != 0, reason="Requires root")
    def test_keyring_structure(self):
        root_keys = SystemHelper.get_keyring_keys(Config.BOOT_ROOT_KEYRING)
        secondary_keys = SystemHelper.get_keyring_keys(Config.SECONDARY_KEYRING)
        for key in root_keys:
            if key.startswith("boot_root:"):
                assert any(key in sk for sk in secondary_keys)


# ============================================================================
# Integration Tests - Hierarchical Sealing
# ============================================================================

@pytest.mark.kernel
@pytest.mark.skipif(os.geteuid() != 0, reason="Requires root")
class TestHierarchicalSealing:
    """Test hierarchical keyring sealing"""

    @pytest.fixture(autouse=True)
    def check_prerequisites(self):
        if not SystemHelper.is_module_loaded():
            pytest.skip("boot_certs not active")
        sealed = SystemHelper.read_sysfs_file("sealed")
        if sealed != "true":
            pytest.skip("Keyrings not sealed")

    def test_cannot_add_root_to_boot_root_certs(self, valid_root_ca):
        key, cert = valid_root_ca
        der = CertificateBuilder.cert_to_der(cert)
        result = SystemHelper.add_key_to_keyring(
            Config.BOOT_ROOT_KEYRING, "test_new_root", der)
        assert not result

    def test_cannot_add_unsigned_cert_to_secondary(self):
        key, cert = CertificateBuilder.create_root_ca("Rogue Root CA")
        der = CertificateBuilder.cert_to_der(cert)
        result = SystemHelper.add_key_to_keyring(
            Config.SECONDARY_KEYRING, "rogue_root", der)
        assert not result


# ============================================================================
# EST/REST Integration Tests (Optional)
# ============================================================================

@pytest.mark.est
class TestESTRESTIntegration:
    """
    Tests for EST (Enrollment over Secure Transport) and REST API.
    These require an external EST service and are skipped by default.
    Run with: pytest -m est --run-est
    """

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_est_simple_enrollment(self):
        pass

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_rest_get_short_term_cert(self):
        pass

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_rest_get_temporary_intermediate(self):
        pass

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_automated_certificate_renewal(self):
        pass


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
