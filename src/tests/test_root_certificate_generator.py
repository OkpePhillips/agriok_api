import os
import unittest
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from certificates.root_cert_generator import RootCertificateGenerator
from certificates.subject import Subject


class TestRootCertificateGenerator(unittest.TestCase):
    def setUp(self):
        """
        Setup temporary directory for certificates and keys.
        """
        self.output_dir = "./test_certs"
        self.generator = RootCertificateGenerator(output_dir=self.output_dir)
        self.subject = Subject(
            common_name="Test Root CA",
            country_name="US",
            state_or_province_name="California",
            locality_name="San Francisco",
            organization_name="Test Org",
        )

    def tearDown(self):
        """
        Cleanup generated files and directories.
        """
        for file_name in os.listdir(self.output_dir):
            file_path = os.path.join(self.output_dir, file_name)
            os.remove(file_path)
        os.rmdir(self.output_dir)

    def test_create_private_key(self):
        """
        Test private key generation and file creation.
        """
        key_name = "test_key"
        key_path = self.generator.create_private_key(key_name)

        # Assert the private key file exists
        self.assertTrue(os.path.isfile(key_path))

        # Load the key to confirm it's valid
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )
            self.assertIsNotNone(private_key)
            self.assertEqual(private_key.key_size, 2048)

    def test_generate_root_certificate(self):
        """
        Test root certificate generation with expected subject attributes and validity.
        """
        key_name = "root_ca_key"
        cert_name = "root_ca_cert.pem"
        valid_after_days = 3650

        # Generate the private key
        self.generator.create_private_key(key_name)
        cert_path = self.generator.generate_root_certificate(
            subject=self.subject,
            key_name=key_name,
            cert_name=cert_name,
            valid_after=valid_after_days,
        )

        # Assert the certificate file exists
        self.assertTrue(os.path.isfile(cert_path))

        # Load the certificate to verify its contents
        with open(cert_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(), backend=default_backend()
            )

        # Check the certificate's subject and issuer match
        subject = cert.subject
        issuer = cert.issuer
        self.assertEqual(subject, issuer)
        self.assertEqual(
            subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "Test Root CA",
        )
        self.assertEqual(
            subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value,
            "Test Org",
        )

        # Check certificate validity period
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        self.assertTrue(not_before <= datetime.now() <= not_after)
        self.assertEqual((not_after - not_before).days, valid_after_days)

        # Check for CA extension
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        self.assertTrue(basic_constraints.ca)

    def test_generate_certificate_with_defaults(self):
        """
        Test generate_certificate method, which should handle both key and certificate generation.
        """
        cert_name = "default_root_ca_cert"
        root_cert = self.generator.generate_certificate(
            self.subject, cert_name=cert_name
        )

        # Assert the generated paths
        self.assertTrue(os.path.isfile(root_cert.CERT_PATH))
        self.assertTrue(os.path.isfile(root_cert.KEY_PATH))

        # Check certificate attributes and validity
        with open(root_cert.CERT_PATH, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(), backend=default_backend()
            )
            subject = cert.subject
            self.assertEqual(
                subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                "Test Root CA",
            )

    def test_invalid_subject_raises_exception(self):
        """
        Test that generating a certificate with an invalid subject raises an exception.
        """
        invalid_subject = Subject(common_name="")  # Missing required details

        with self.assertRaises(ValueError):
            self.generator.generate_certificate(invalid_subject, "invalid_cert")

    def test_invalid_output_directory(self):
        """
        Test handling of an invalid output directory.
        """
        # Attempt to initialize with an invalid directory path
        invalid_output_dir = "/invalid_directory_path"
        with self.assertRaises(OSError):
            RootCertificateGenerator(output_dir=invalid_output_dir)

    def test_cert_file_permissions(self):
        """
        Ensure the generated certificate files have secure permissions.
        """
        key_name = "secure_key"
        cert_name = "secure_cert.pem"

        # Generate key and certificate
        key_path = self.generator.create_private_key(key_name)
        cert_path = self.generator.generate_root_certificate(
            subject=self.subject, key_name=key_name, cert_name=cert_name
        )

        # Check file permissions
        self.assertTrue(os.path.isfile(key_path))
        self.assertTrue(os.path.isfile(cert_path))
        cert_permissions = os.stat(cert_path).st_mode
        key_permissions = os.stat(key_path).st_mode

        # Ensure files are only readable and writable by the owner
        self.assertEqual(oct(key_permissions)[-3:], "600")
        self.assertEqual(oct(cert_permissions)[-3:], "600")


if __name__ == "__main__":
    unittest.main()
