import unittest
from certificates import (
    Cert,
    ClientCert,
    RootCert,
)  # Replace 'your_module' with the actual module name


class TestCertInitialization(unittest.TestCase):

    def test_client_cert_initialization(self):
        """Test that the ClientCert class initializes with all paths."""
        cert_path = "path/to/client_cert.pem"
        key_path = "path/to/client_key.pem"
        ca_cert_path = "path/to/ca_cert.pem"
        csr_path = "path/to/csr.pem"

        client_cert = ClientCert(cert_path, key_path, ca_cert_path, csr_path)

        self.assertEqual(client_cert.CERT_PATH, cert_path)
        self.assertEqual(client_cert.KEY_PATH, key_path)
        self.assertEqual(client_cert.CA_CERT_PATH, ca_cert_path)
        self.assertEqual(client_cert.CSR_PATH, csr_path)

    def test_root_cert_initialization(self):
        """Test that the RootCert class initializes with cert and key paths."""
        cert_path = "path/to/root_cert.pem"
        key_path = "path/to/root_key.pem"

        root_cert = RootCert(cert_path, key_path)

        self.assertEqual(root_cert.CERT_PATH, cert_path)
        self.assertEqual(root_cert.KEY_PATH, key_path)

    def test_client_cert_inherits_cert(self):
        """Ensure that ClientCert is a subclass of Cert."""
        self.assertTrue(issubclass(ClientCert, Cert))

    def test_root_cert_inherits_cert(self):
        """Ensure that RootCert is a subclass of Cert."""
        self.assertTrue(issubclass(RootCert, Cert))


if __name__ == "__main__":
    unittest.main()
