from abc import ABC
import os


class Cert(ABC):
    """
    Base class for handling certificate and key file paths.

    Attributes:
        CERT_PATH (str): Path to the X.509 certificate file.
        KEY_PATH (str): Path to the private key file.
        CA_CERT_PATH (str): Path to the CA certificate file.
        CSR_PATH (str): Path to the Certificate Signing Request (CSR) file.
    """

    def __init__(
        self, cert_path=None, key_path=None, ca_cert_path=None, csr_path=None
    ) -> None:
        """
        Initializes the Cert instance with specified file paths.

        Parameters:
            cert_path (str): Path to the X.509 certificate file.
            key_path (str): Path to the private key file.
            ca_cert_path (str): Path to the CA certificate file.
            csr_path (str): Path to the CSR file.
        """
        self.CERT_PATH = cert_path
        self.KEY_PATH = key_path
        self.CA_CERT_PATH = ca_cert_path
        self.CSR_PATH = csr_path

    @classmethod
    def get_cert(
        cls, dir, cert_name=None, key_name=None, ca_cert_name=None, csr_name=None
    ):
        """
        Class method to create a Cert instance using directory paths and optional file names.

        Parameters:
            dir (str): Directory where the certificate, key, CA certificate, and CSR files are located.
            cert_name (str): Name of the certificate file (without extension).
            key_name (str): Name of the private key file (without extension).
            ca_cert_name (str): Name of the CA certificate file (without extension).
            csr_name (str): Name of the CSR file (without extension).

        Returns:
            Cert: A new instance of the Cert class with the specified paths.
        """
        # Construct file paths if names are provided
        if key_name:
            key_path = os.path.join(dir, f"{key_name}.key")
        if cert_name:
            cert_path = os.path.join(dir, f"{cert_name}.pem")
        if ca_cert_name:
            ca_cert_path = os.path.join(dir, f"{ca_cert_name}.pem")
        if csr_name:
            csr_path = os.path.join(dir, f"{csr_name}.pem")

        return cls(cert_path, key_path, ca_cert_path, csr_path)


class ClientCert(Cert):
    """
    Certificate class specifically for client certificates, extending Cert.
    """

    def __init__(
        self, cert_path=None, key_path=None, ca_cert_path=None, csr_path=None
    ) -> None:
        """
        Initializes a ClientCert instance with paths for client certificate, key, CA cert, and CSR.

        Parameters:
            cert_path (str): Path to the client's certificate file.
            key_path (str): Path to the client's private key file.
            ca_cert_path (str): Path to the CA certificate file.
            csr_path (str): Path to the client's CSR file.
        """
        super().__init__(cert_path, key_path, ca_cert_path, csr_path)


class RootCert(Cert):
    """
    Certificate class specifically for root certificates, extending Cert.
    """

    def __init__(self, cert_path=None, key_path=None) -> None:
        """
        Initializes a RootCert instance with paths for the root certificate and key.

        Parameters:
            cert_path (str): Path to the root certificate file.
            key_path (str): Path to the root private key file.
        """
        super().__init__(cert_path, key_path)
