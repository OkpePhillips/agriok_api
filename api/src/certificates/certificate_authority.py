from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
)
from cryptography.hazmat.primitives import serialization

from datetime import datetime, timedelta


class CertificateAuthority:
    """
    Manages a Certificate Authority (CA) to handle loading CA certificates and keys,
    and signing Certificate Signing Requests (CSRs) for client or server authentication.

    Attributes:
        cert_file (str): Path to the CA certificate file.
        key_file (str): Path to the CA private key file.
        ca_key (rsa.RSAPrivateKey): The loaded private key for signing.
        ca_cert (x509.Certificate): The loaded CA certificate.
    """

    def __init__(self, cert_path: str, key_path: str) -> None:
        """
        Initialize the CertificateAuthority with paths to the CA certificate and private key.

        Parameters:
            cert_path (str): Path to the x.509 CA certificate file.
            key_path (str): Path to the CA's private key file.
        """
        self.cert_file: str = cert_path
        self.key_file: str = key_path
        self.ca_key = self._load_key(key_path)
        self.ca_cert = self._load_cert(cert_path)

    def _load_cert(self, cert_path: str) -> x509.Certificate:
        """
        Load the CA certificate from a PEM file.

        Parameters:
            cert_path (str): Path to the CA certificate file.

        Returns:
            x509.Certificate: Loaded x.509 CA certificate.
        """
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def _load_key(self, key_path: str) -> rsa.RSAPrivateKey:
        """
        Load the CA private key from a PEM file.

        Parameters:
            key_path (str): Path to the CA private key file.

        Returns:
            rsa.RSAPrivateKey: Loaded RSA private key.
        """
        with open(key_path, "rb") as f:
            return load_pem_private_key(f.read(), password=None)

    def sign_csr(
        self, csr_path: str, signed_cert_path: str, valid_after: int = 365
    ) -> str:
        """
        Sign a Certificate Signing Request (CSR) using the CA's private key, creating a certificate.

        Parameters:
            csr_path (str): Path to the CSR file to be signed.
            signed_cert_path (str): Path where the signed certificate will be saved.
            valid_after (int): Number of days the signed certificate is valid for. Default is 365.

        Returns:
            str: Path to the newly created signed certificate.
        """
        # Load the CSR
        with open(csr_path, "rb") as f:
            try:
                csr = x509.load_pem_x509_csr(f.read())
            except ValueError as e:
                raise ValueError("Invalid CSR file format") from e
            except Exception as e:
                raise Exception(f"An unexpected error occurred: {e}") from e

        # Validate CSR signature
        if not csr.is_signature_valid:
            raise ValueError("Invalid CSR signature")

        # Create the certificate using the CSR's subject and public key
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=valid_after))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(private_key=self.ca_key, algorithm=hashes.SHA256())
        )

        # Write the signed certificate to a file
        with open(signed_cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

        return signed_cert_path

    def get_cert(self) -> str:
        """
        Retrieve the CA certificate file path.

        Returns:
            str: Path to the CA certificate file.
        """
        return self.cert_file
