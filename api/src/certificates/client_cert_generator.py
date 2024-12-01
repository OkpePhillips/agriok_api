from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from .base_cert_generator import CertificateGenerator
from .subject import Subject
from .certificate_authority import CertificateAuthority
from .cert_models import ClientCert
from typing import Optional
import shutil
import os


class ClientCertificateGenerator(CertificateGenerator):
    """
    Handles the creation of client certificates by generating Certificate Signing Requests (CSRs)
    and obtaining signed certificates from a Certificate Authority (CA).
    """

    def create_csr(
        self,
        subject: Subject,
        key_name: Optional[str] = None,
        key_path: Optional[str] = None,
    ) -> str:
        """
        Creates a CSR (Certificate Signing Request) for the client and saves it.

        Parameters:
            subject (Subject): The subject attributes for the CSR (e.g., country, organization).
            key_name (Optional[str]): The name for the client's private key file (if not provided, `key_path` must be given).
            key_path (Optional[str]): Path to the client's existing private key file.

        Returns:
            str: Path to the saved CSR file.
        """
        if not (key_name or key_path):
            raise ValueError("Either key_name or key_path must be set")

        # Generate or load the private key for the client
        key_path = key_path or self.create_private_key(key_name)

        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        # Create the CSR with specified subject attributes
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COUNTRY_NAME, subject.get("country_name")
                        ),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME,
                            subject.get("state_or_province_name"),
                        ),
                        x509.NameAttribute(
                            NameOID.LOCALITY_NAME, subject.get("locality_name")
                        ),
                        x509.NameAttribute(
                            NameOID.ORGANIZATION_NAME, subject.get("organization_name")
                        ),
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, subject.get("common_name")
                        ),
                    ]
                )
            )
            .sign(private_key, hashes.SHA256())
        )

        # Save CSR to a file
        csr_path = os.path.join(self.output_dir, f"{key_name}_csr.pem")
        with open(csr_path, "wb") as csr_file:
            csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

        return csr_path

    def get_signed_csr(
        self, ca_object: CertificateAuthority, csr_path: str, signed_cert_name: str
    ) -> str:
        """
        Sends the CSR to a CA object to be signed and saves the signed certificate.

        Parameters:
            ca_object (CertificateAuthority): The Certificate Authority object with a method to sign CSRs.
            csr_path (str): The path to the CSR file.
            signed_cert_name (str): The name for the signed certificate file.

        Returns:
            str: Path to the signed certificate.
        """
        signed_cert_path = os.path.join(self.output_dir, f"{signed_cert_name}.pem")
        ca_object.sign_csr(csr_path, signed_cert_path)

        return signed_cert_path

    def generate_certificate(self, subject: Subject, key_name: str) -> ClientCert:
        """
        Generates a client certificate by creating a CSR and associating it with the client.

        Parameters:
            subject (Subject): The subject details for the certificate (e.g., name, organization).
            key_name (str): Name of the client's private key file.

        Returns:
            ClientCert: A ClientCert instance representing the generated CSR and key paths.
        """
        key_path = self.create_private_key(key_name)
        csr_path = self.create_csr(subject, key_name=key_name, key_path=key_path)

        return ClientCert(key_path=key_path, csr_path=csr_path)

    def generate_signed_certificate(
        self, subject: Subject, ca: CertificateAuthority, key_name: str, cert_name: str
    ) -> ClientCert:
        """
        Generates a client certificate, creates a CSR, and obtains a signed certificate from the CA.

        Parameters:
            subject (Subject): The subject attributes for the CSR (e.g., country, organization).
            ca (CertificateAuthority): The Certificate Authority object for signing.
            key_name (str): Name for the client's private key file.
            cert_name (str): Name for the signed certificate file.

        Returns:
            ClientCert: A ClientCert instance representing the signed certificate, key, CA certificate, and CSR paths.
        """
        key_path = self.create_private_key(key_name)
        csr_path = self.create_csr(subject, key_name=key_name, key_path=key_path)
        cert_path = self.get_signed_csr(ca, csr_path, cert_name)
        ca_cert_path = self.copy_ca_cert(ca)
        print(ca_cert_path)

        return ClientCert(
            cert_path=cert_path,
            key_path=key_path,
            ca_cert_path=ca_cert_path,
            csr_path=csr_path,
        )
    
    def copy_ca_cert(self, ca: CertificateAuthority):
        src = ca.get_cert()
        dest = os.path.join(self.output_dir, os.path.basename(src))
        shutil.copy(src, dest)

        return dest