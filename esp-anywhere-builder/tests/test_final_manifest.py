"""Regression test for the exact bytes published as an OTA manifest."""
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parents[1] / "rootfs" / "app"))
from app import Builder
from ha_verifier.manifest import parse_and_verify_manifest


class FinalManifestTest(unittest.TestCase):
    def test_final_serialized_manifest_passes_home_assistant_parser(self) -> None:
        private = Ed25519PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )).decode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            firmware = Path(temporary) / "firmware-0.1.8.ota.bin"
            firmware.write_bytes(b"synthetic firmware fixture")
            document = Builder._manifest(
                "0.1.8", "esp32c3_supermini_oled", "a" * 40, firmware,
                "kaziksiwy-stack/esp-anywhere-ota", "firmware-prod-2026-01", private,
            )
            final_bytes = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        verified = parse_and_verify_manifest(
            final_bytes,
            trusted_key_id="firmware-prod-2026-01",
            trusted_public_key=public,
            expected_hardware_profile="esp32c3_supermini_oled",
        )
        self.assertEqual("0.1.8", verified.version)


if __name__ == "__main__":
    unittest.main()
