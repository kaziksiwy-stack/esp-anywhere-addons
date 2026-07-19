from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

import app


class ConfigSnapshotTest(unittest.TestCase):
    def test_fresh_multiline_ca_and_invalid_ca(self):
        key = Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Builder test CA")])
        now = datetime.now(timezone.utc)
        pem = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
               .sign(key, algorithm=None).public_bytes(serialization.Encoding.PEM).decode())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "source"; source.mkdir()
            yaml_bytes = b"mqtt:\n  certificate_authority: !secret mqtt_ca_certificate\n"
            secrets_bytes = ("mqtt_ca_certificate: |-\n" + "".join("  " + line + "\n" for line in pem.splitlines())).encode()
            (source / "device.yaml").write_bytes(yaml_bytes)
            (source / "secrets.yaml").write_bytes(secrets_bytes)
            previous = app.CONFIG_DIR; app.CONFIG_DIR = source
            try:
                destination = root / "snapshot"
                app.Builder.__new__(app.Builder)._copy_config(destination, "device.yaml")
                self.assertEqual((destination / "device.yaml").read_bytes(), yaml_bytes)
                self.assertEqual((destination / "secrets.yaml").read_bytes(), secrets_bytes)
                (source / "secrets.yaml").write_text("mqtt_ca_certificate: not-a-certificate\n")
                with self.assertRaisesRegex(ValueError, "not valid X.509 PEM"):
                    app.Builder.__new__(app.Builder)._copy_config(root / "invalid", "device.yaml")
            finally:
                app.CONFIG_DIR = previous


if __name__ == "__main__":
    unittest.main()
