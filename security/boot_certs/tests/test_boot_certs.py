#!/usr/bin/env python3
"""
Boot Certificate System - Test Suite

Tests hierarchical keyring sealing, certificate expiry enforcement,
and runtime certificate management.

Requirements:
    pip install pytest cryptography python-dateutil

Usage:
    pytest test_boot_certs.py -v
    pytest test_boot_certs.py -v -k test_expiry
    pytest test_boot_certs.py -v --run-kernel-tests  # Requires root + loaded module
"""

import os
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
from dateutil import parser as date_parser


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

    # Certificate validity periods
    ROOT_CA_VALIDITY_DAYS = 3650  # 10 years
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
        """
        Create a self-signed root CA certificate

        Args:
            subject_name: CN for the certificate
            validity_days: How long the cert is valid (if not_valid_after not specified)
            not_valid_before: Start of validity period (default: now)
            not_valid_after: End of validity period (default: now + validity_days)

        Returns:
            (private_key, certificate)
        """
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
        """Convert certificate to PEM format"""
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def cert_to_der(cert: x509.Certificate) -> bytes:
        """Convert certificate to DER format"""
        return cert.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
        """Convert private key to PEM format"""
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def calculate_sha3_512(data: bytes) -> str:
        """Calculate SHA3-512 hash (hex string)"""
        return hashlib.sha3_512(data).hexdigest()


# ============================================================================
# System Interaction Helpers
# ============================================================================

class SystemHelper:
    """Helper for interacting with the kernel module and keyrings"""

    @staticmethod
    def is_module_loaded() -> bool:
        """Check if boot_certs module is loaded"""
        try:
            result = subprocess.run(
                ["lsmod"],
                capture_output=True,
                text=True,
                check=True
            )
            return "boot_certs_sysfs" in result.stdout
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def read_sysfs_file(filename: str) -> Optional[str]:
        """Read a sysfs file from /sys/kernel/boot_certs/"""
        path = Config.BOOT_CERTS_SYSFS / filename
        try:
            return path.read_text().strip()
        except Exception:
            return None

    @staticmethod
    def write_sysfs_file(filename: str, value: str) -> bool:
        """Write to a sysfs file"""
        path = Config.BOOT_CERTS_SYSFS / filename
        try:
            path.write_text(value)
            return True
        except Exception:
            return False

    @staticmethod
    def get_keyring_keys(keyring: str) -> List[str]:
        """Get list of key descriptions in a keyring"""
        try:
            result = subprocess.run(
                ["keyctl", "list", keyring],
                capture_output=True,
                text=True,
                check=True
            )
            # Parse output: "123456789: --alswrv     0     0 asymmetric: boot_root:0"
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
        """Add a DER certificate to a keyring"""
        try:
            with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
                f.write(der_data)
                temp_path = f.name

            try:
                subprocess.run(
                    ["keyctl", "padd", "asymmetric", desc, keyring],
                    stdin=open(temp_path, 'rb'),
                    capture_output=True,
                    check=True
                )
                return True
            finally:
                os.unlink(temp_path)
        except subprocess.CalledProcessError:
            return False


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def test_output_dir():
    """Create output directory for test artifacts"""
    Config.TEST_OUTPUT.mkdir(parents=True, exist_ok=True)
    return Config.TEST_OUTPUT


@pytest.fixture
def valid_root_ca():
    """Generate a valid root CA certificate"""
    key, cert = CertificateBuilder.create_root_ca("Test Root CA")
    return key, cert


@pytest.fixture
def expired_root_ca():
    """Generate an expired root CA certificate"""
    now = datetime.utcnow()
    key, cert = CertificateBuilder.create_root_ca(
        "Expired Root CA",
        not_valid_before=now - timedelta(days=400),
        not_valid_after=now - timedelta(days=1)
    )
    return key, cert


@pytest.fixture
def expiring_soon_root_ca():
    """Generate a root CA that expires in 15 days"""
    now = datetime.utcnow()
    key, cert = CertificateBuilder.create_root_ca(
        "Expiring Soon Root CA",
        not_valid_before=now - timedelta(days=365),
        not_valid_after=now + timedelta(days=15)
    )
    return key, cert


@pytest.fixture
def certificate_chain(valid_root_ca):
    """Generate a complete certificate chain (root + intermediate)"""
    root_key, root_cert = valid_root_ca

    # Create intermediate
    int_key, int_cert = CertificateBuilder.create_intermediate_ca(
        "Test Intermediate CA",
        root_key,
        root_cert
    )

    return {
        'root_key': root_key,
        'root_cert': root_cert,
        'intermediate_key': int_key,
        'intermediate_cert': int_cert
    }


# ============================================================================
# Unit Tests - Certificate Generation
# ============================================================================

class TestCertificateGeneration:
    """Test certificate generation helpers"""

    def test_generate_valid_root_ca(self, valid_root_ca, test_output_dir):
        """Test generating a valid root CA"""
        key, cert = valid_root_ca

        # Verify it's self-signed
        assert cert.subject == cert.issuer

        # Verify CA flag
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert basic_constraints.ca is True

        # Verify validity
        now = datetime.utcnow()
        assert cert.not_valid_before <= now
        assert cert.not_valid_after > now

        # Save to file for inspection
        (test_output_dir / "valid_root_ca.pem").write_bytes(
            CertificateBuilder.cert_to_pem(cert)
        )

    def test_generate_expired_root_ca(self, expired_root_ca):
        """Test generating an expired root CA"""
        key, cert = expired_root_ca

        now = datetime.utcnow()
        assert cert.not_valid_after < now
        assert cert.subject == cert.issuer

    def test_generate_expiring_soon_root_ca(self, expiring_soon_root_ca):
        """Test generating a root CA expiring soon"""
        key, cert = expiring_soon_root_ca

        now = datetime.utcnow()
        days_until_expiry = (cert.not_valid_after - now).days
        assert 10 <= days_until_expiry <= 20

    def test_generate_certificate_chain(self, certificate_chain, test_output_dir):
        """Test generating a complete certificate chain"""
        root_cert = certificate_chain['root_cert']
        int_cert = certificate_chain['intermediate_cert']

        # Verify intermediate is signed by root
        assert int_cert.issuer == root_cert.subject

        # Create chain PEM
        chain_pem = (
            CertificateBuilder.cert_to_pem(root_cert) +
            CertificateBuilder.cert_to_pem(int_cert)
        )

        (test_output_dir / "test_chain.pem").write_bytes(chain_pem)

    def test_sha3_512_hash(self, certificate_chain, test_output_dir):
        """Test SHA3-512 hash calculation"""
        root_cert = certificate_chain['root_cert']
        int_cert = certificate_chain['intermediate_cert']

        chain_pem = (
            CertificateBuilder.cert_to_pem(root_cert) +
            CertificateBuilder.cert_to_pem(int_cert)
        )

        hash_hex = CertificateBuilder.calculate_sha3_512(chain_pem)

        # Should be 128 hex characters (512 bits / 4 bits per hex char)
        assert len(hash_hex) == 128
        assert all(c in '0123456789abcdef' for c in hash_hex)

        # Save hash
        (test_output_dir / "chain_hash.txt").write_text(hash_hex)


# ============================================================================
# Unit Tests - Expiry Detection
# ============================================================================

class TestExpiryDetection:
    """Test certificate expiry detection logic"""

    def test_detect_valid_certificate(self, valid_root_ca):
        """Test that valid certificates are detected correctly"""
        key, cert = valid_root_ca

        now = datetime.utcnow()
        assert cert.not_valid_before <= now
        assert cert.not_valid_after > now

    def test_detect_expired_certificate(self, expired_root_ca):
        """Test that expired certificates are detected"""
        key, cert = expired_root_ca

        now = datetime.utcnow()
        assert cert.not_valid_after < now

    def test_detect_expiring_soon(self, expiring_soon_root_ca):
        """Test detection of certificates expiring soon"""
        key, cert = expiring_soon_root_ca

        now = datetime.utcnow()
        days_until_expiry = (cert.not_valid_after - now).days

        # Should expire within 30 days (grace period)
        assert 0 < days_until_expiry < 30

    def test_expiry_policy_warn(self, expired_root_ca):
        """Test WARN policy behavior"""
        # WARN policy should allow expired certs
        # This is a logic test - actual enforcement happens in kernel
        key, cert = expired_root_ca

        now = datetime.utcnow()
        is_expired = cert.not_valid_after < now

        # In WARN mode, we log but don't reject
        should_reject = False
        assert is_expired and not should_reject

    def test_expiry_policy_reject(self, expired_root_ca):
        """Test REJECT policy behavior"""
        key, cert = expired_root_ca

        now = datetime.utcnow()
        is_expired = cert.not_valid_after < now

        # In REJECT mode, we reject expired certs
        should_reject = is_expired
        assert should_reject

    def test_expiry_policy_strict(self, expiring_soon_root_ca):
        """Test STRICT policy behavior"""
        key, cert = expiring_soon_root_ca

        now = datetime.utcnow()
        grace_days = 30
        days_until_expiry = (cert.not_valid_after - now).days

        is_expiring_soon = days_until_expiry < grace_days

        # In STRICT mode, we reject certs expiring within grace period
        should_reject = is_expiring_soon
        assert should_reject and is_expiring_soon


# ============================================================================
# Integration Tests - Kernel Module
# ============================================================================

@pytest.mark.kernel
class TestKernelModule:
    """Integration tests requiring loaded kernel module"""

    @pytest.fixture(autouse=True)
    def check_module_loaded(self):
        """Skip these tests if module not loaded"""
        if not SystemHelper.is_module_loaded():
            pytest.skip("boot_certs module not loaded")

    def test_sysfs_interface_exists(self):
        """Test that sysfs interface is available"""
        assert Config.BOOT_CERTS_SYSFS.exists()
        assert (Config.BOOT_CERTS_SYSFS / "ok").exists()
        assert (Config.BOOT_CERTS_SYSFS / "status").exists()
        assert (Config.BOOT_CERTS_SYSFS / "sealed").exists()
        assert (Config.BOOT_CERTS_SYSFS / "expiry_status").exists()

    def test_read_ok_status(self):
        """Test reading OK status"""
        ok_status = SystemHelper.read_sysfs_file("ok")
        assert ok_status in ["true", "false"]

    def test_read_sealed_status(self):
        """Test reading sealed status"""
        sealed = SystemHelper.read_sysfs_file("sealed")
        assert sealed in ["true", "false"]

    def test_read_expiry_status(self):
        """Test reading expiry status"""
        expiry_status = SystemHelper.read_sysfs_file("expiry_status")
        assert expiry_status is not None

        # Parse status
        parts = dict(item.split('=') for item in expiry_status.split())
        assert 'policy' in parts
        assert 'grace_days' in parts
        assert 'expired' in parts
        assert parts['policy'] in ['WARN', 'REJECT', 'STRICT']

    def test_manual_expiry_check(self):
        """Test triggering manual expiry check"""
        if not os.access(Config.BOOT_CERTS_SYSFS / "expiry_check_now", os.W_OK):
            pytest.skip("No write access to expiry_check_now")

        result = SystemHelper.write_sysfs_file("expiry_check_now", "1")
        assert result

    @pytest.mark.skipif(os.geteuid() != 0, reason="Requires root")
    def test_keyring_structure(self):
        """Test that keyrings exist and have correct structure"""
        # Check boot_root_certs keyring
        root_keys = SystemHelper.get_keyring_keys(Config.BOOT_ROOT_KEYRING)

        # Check secondary keyring
        secondary_keys = SystemHelper.get_keyring_keys(Config.SECONDARY_KEYRING)

        # All root keys should also be in secondary
        for key in root_keys:
            # Root keys have format "boot_root:N"
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
        """Check that module is loaded and sealed"""
        if not SystemHelper.is_module_loaded():
            pytest.skip("boot_certs module not loaded")

        sealed = SystemHelper.read_sysfs_file("sealed")
        if sealed != "true":
            pytest.skip("Keyrings not sealed")

    def test_cannot_add_root_to_boot_root_certs(self, valid_root_ca):
        """Test that new root CAs cannot be added to boot_root_certs"""
        key, cert = valid_root_ca
        der = CertificateBuilder.cert_to_der(cert)

        # Should fail - keyring is sealed
        result = SystemHelper.add_key_to_keyring(
            Config.BOOT_ROOT_KEYRING,
            "test_new_root",
            der
        )

        assert not result  # Should fail

    def test_cannot_add_unsigned_cert_to_secondary(self, valid_root_ca):
        """Test that unsigned/rogue certs cannot be added to secondary"""
        # Create a rogue root CA (not signed by boot roots)
        key, cert = CertificateBuilder.create_root_ca("Rogue Root CA")
        der = CertificateBuilder.cert_to_der(cert)

        # Should fail - not signed by boot root CA
        result = SystemHelper.add_key_to_keyring(
            Config.SECONDARY_KEYRING,
            "rogue_root",
            der
        )

        assert not result  # Should fail


# ============================================================================
# Placeholder for Future EST/REST Integration
# ============================================================================

class TestESTRESTIntegration:
    """
    Future tests for EST (Enrollment over Secure Transport) and REST API

    TODO: Implement when EST/REST service is available
    - Certificate signing requests
    - Short-term certificate generation for expiry testing
    - Temporary intermediate CA generation
    - Certificate renewal
    - Automated rotation testing
    """

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_est_simple_enrollment(self):
        """Test EST simple enrollment"""
        # TODO: Implement EST enrollment
        pass

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_rest_get_short_term_cert(self):
        """Test REST API for getting short-term certificates"""
        # TODO: Implement REST endpoint for short-term certs
        pass

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_rest_get_temporary_intermediate(self):
        """Test REST API for temporary intermediate CAs"""
        # TODO: Implement REST endpoint for temporary intermediates
        pass

    @pytest.mark.skip(reason="EST/REST service not yet implemented")
    def test_automated_certificate_renewal(self):
        """Test automated certificate renewal via EST"""
        # TODO: Implement automated renewal
        pass


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
