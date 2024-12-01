from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from .base_cert_generator import CertificateGenerator
from .cert_models import RootCert
from .subject import Subject
import os


class RootCertificateGenerator(CertificateGenerator):
    """
    Generates a self-signed root certificate and RSA private key for use as a Root Certificate Authority (CA).
    """

    def generate_root_certificate(
        self,
        subject: Subject,
        key_name: str,
        cert_name: str = "root_ca_cert",
        valid_after: int = 3650,
    ) -> str:
        """
        Generates a self-signed root certificate with the specified subject and validity period.

        Parameters:
            subject (Subject): The subject information for the certificate (e.g., country, organization).
            key_name (str): The name of the private key file for the root certificate.
            cert_name (str): Name for the certificate file (default is "root_ca_cert").
            valid_after (int): Validity period for the certificate in days (default is 3650, or 10 years).

        Returns:
            str: Path to the saved root certificate file.
        """
        # Generate or load the private key for signing
        key_path = os.path.join(self.output_dir, f"{key_name}.key")
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        # Set up the certificate subject and issuer (self-signed, so both are the same)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, subject.get("country_name")),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME,
                    subject.get("state_or_province_name"),
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, subject.get("locality_name")),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, subject.get("organization_name")
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, subject.get("common_name")),
            ]
        )

        # Create a self-signed certificate
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(
                datetime.now() + timedelta(days=valid_after)
            )  # e.g., 10 years validity
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )

        # Save the certificate to a file
        cert_path = os.path.join(self.output_dir, f"{cert_name}.pem")
        fd = os.open(
            cert_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )  # Secure file permissions
        with os.fdopen(fd, "wb") as cert_file:
            cert_file.write(root_cert.public_bytes(encoding=serialization.Encoding.PEM))

        return cert_path

    def generate_certificate(
        self,
        subject: Subject,
        key_name: str = "root_ca",
        cert_name: str = "root_ca_cert",
        valid_after: int = 3650,
    ) -> RootCert:
        """
        High-level method to generate both a private key and self-signed root certificate for a Root CA.

        Parameters:
            subject (Subject): The subject details for the certificate (e.g., organization, common name).
            key_name (str): Name for the private key file (default is "root_ca").
            cert_name (str): Name for the root certificate file (default is "root_ca_cert").
            valid_after (int): Number of days the certificate will be valid (default is 3650).

        Returns:
            RootCert: Instance of `RootCert` containing paths to the certificate and private key files.
        """
        key_path = self.create_private_key(key_name)
        cert_path = self.generate_root_certificate(
            subject, key_name, cert_name, valid_after
        )

        return RootCert(cert_path, key_path)
