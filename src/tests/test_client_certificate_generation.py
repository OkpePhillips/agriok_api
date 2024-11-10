from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from certificates import (
    ClientCertificateGenerator,
    Subject,
    CertificateAuthority,
    ClientCert,
)  # Adjust import as necessary
from datetime import datetime, timedelta
import unittest
import os


class TestClientCertificateGenerator(unittest.TestCase):

    def setUp(self):
        """Set up instance method to create a test instance of ClientCertificateGenerator."""
        self.output_dir = "test_output"
        os.makedirs(
            self.output_dir, exist_ok=True
        )  # Create output directory if it doesn't exist

        self.generator = ClientCertificateGenerator(self.output_dir)

        self.subject = Subject(
            common_name="Test Client",
            country_name="US",
            state_or_province_name="California",
            locality_name="San Francisco",
            organization_name="Test Org",
        )

        # Create a mock CertificateAuthority
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_cert_path = os.path.join(self.output_dir, "ca_cert.pem")
        self.ca_key_path = os.path.join(self.output_dir, "ca_key.pem")

        # Create a mock CA cert and key
        with open(self.ca_key_path, "wb") as f:
            f.write(
                self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Create a self-signed CA certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA"),
            ]
        )

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        # Save the CA certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        self.ca = CertificateAuthority(self.ca_cert_path, self.ca_key_path)

    def tearDown(self):
        """Clean up test output directory."""
        for filename in os.listdir(self.output_dir):
            file_path = os.path.join(self.output_dir, filename)
            os.remove(file_path)
        os.rmdir(self.output_dir)

    def test_create_csr(self):
        """Test creating a CSR."""
        csr_path = self.generator.create_csr(self.subject, key_name="test_client_key")
        self.assertTrue(os.path.isfile(csr_path))

        # Verify CSR content
        with open(csr_path, "rb") as csr_file:
            csr = x509.load_pem_x509_csr(csr_file.read())
        self.assertEqual(
            csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "Test Client",
        )

    def test_generate_signed_certificate(self):
        """Test generating a signed client certificate."""
        signed_cert_name = "signed_client_cert"
        client_cert = self.generator.generate_signed_certificate(
            self.subject,
            self.ca,
            key_name="test_client_key",
            cert_name=signed_cert_name,
        )

        self.assertTrue(os.path.isfile(client_cert.CA_CERT_PATH))
        self.assertTrue(os.path.isfile(client_cert.KEY_PATH))
        self.assertTrue(os.path.isfile(client_cert.CSR_PATH))

        # Verify signed certificate content
        with open(client_cert.CA_CERT_PATH, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read())
        self.assertEqual(
            cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "Test CA",
        )

    def test_invalid_csr(self):
        """Test that an invalid CSR raises an exception."""
        with open("invalid_csr.pem", "wb") as f:
            f.write(b"not a valid csr")

        with self.assertRaises(ValueError) as context:
            self.generator.get_signed_csr(
                self.ca, "invalid_csr.pem", "signed_client_cert"
            )

        os.remove("invalid_csr.pem")

    def test_missing_key_name(self):
        """Test that create_csr raises an error if both key_name and key_path are None."""
        with self.assertRaises(ValueError) as context:
            self.generator.create_csr(self.subject, key_name=None, key_path=None)
        self.assertEqual(
            str(context.exception), "Either key_name or key_path must be set"
        )


if __name__ == "__main__":
    unittest.main()
