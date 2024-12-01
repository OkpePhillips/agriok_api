import unittest
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from certificates import (
    CertificateAuthority,
)  # Replace 'your_module' with the actual module name


class TestCertificateAuthority(unittest.TestCase):
    def setUp(self):
        """Set up test files for the CertificateAuthority tests."""
        # Generate a dummy CA key and certificate for testing
        self.ca_key_path = "test_ca_key.pem"
        self.ca_cert_path = "test_ca_cert.pem"

        # Generate a new private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Save the CA private key
        with open(self.ca_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),  # No password,
                )
            )

        # Create a self-signed CA certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
            ]
        )

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(self.private_key, hashes.SHA256())
        )

        # Save the CA certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        # Initialize CertificateAuthority
        self.ca = CertificateAuthority(self.ca_cert_path, self.ca_key_path)

    def tearDown(self):
        """Clean up the test files."""
        os.remove(self.ca_key_path)
        os.remove(self.ca_cert_path)

    def test_initialization(self):
        """Test that the CertificateAuthority initializes correctly."""
        self.assertIsNotNone(self.ca.ca_cert)
        self.assertIsNotNone(self.ca.ca_key)

    def test_load_cert(self):
        """Test that the CA certificate loads correctly."""
        cert = self.ca._load_cert(self.ca_cert_path)
        self.assertIsInstance(cert, x509.Certificate)

    def test_load_key(self):
        """Test that the CA private key loads correctly."""
        key = self.ca._load_key(self.ca_key_path)
        self.assertIsNotNone(key)

    def test_sign_csr(self):
        """Test signing a valid CSR."""
        # Create a dummy CSR for testing
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
                    ]
                )
            )
            .sign(key, hashes.SHA256())
        )

        csr_path = "test_csr.pem"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        signed_cert_path = "test_signed_cert.pem"
        signed_cert = self.ca.sign_csr(csr_path, signed_cert_path)

        # Check if the signed certificate was created
        self.assertTrue(os.path.isfile(signed_cert))
        self.assertEqual(signed_cert, signed_cert_path)

        # Clean up
        os.remove(csr_path)
        os.remove(signed_cert_path)

    def test_sign_invalid_csr(self):
        """Test that signing an invalid CSR raises a ValueError."""
        invalid_csr_path = "invalid_csr.pem"
        with open(invalid_csr_path, "wb") as f:
            f.write(b"Invalid CSR data")

        with self.assertRaises(ValueError) as context:
            self.ca.sign_csr(invalid_csr_path, "test_signed_cert.pem")

        # Clean up
        os.remove(invalid_csr_path)

    def test_get_cert(self):
        """Test that get_cert returns the correct certificate path."""
        self.assertEqual(self.ca.get_cert(), self.ca_cert_path)


if __name__ == "__main__":
    unittest.main()
