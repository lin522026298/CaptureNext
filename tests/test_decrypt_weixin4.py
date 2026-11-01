import hashlib
import hmac
from pathlib import Path
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tools.decrypt_weixin4_database import decrypt_page, decrypt_copy
from tools.verify_weixin4_database import derive_mac_key


class DecryptTests(unittest.TestCase):
    def test_exact_page_round_trip_and_tamper_rejection(self):
        key, salt, iv = bytes(range(32)), bytes(range(16)), bytes(reversed(range(16)))
        for number in (1, 2, 108):
            start = 16 if number == 1 else 0
            data = bytes((i * 7) % 256 for i in range(4096 - 80 - start))
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            encrypted = (salt if number == 1 else b"") + cipher.update(data) + cipher.finalize() + iv
            digest = hmac.new(derive_mac_key(key, salt), encrypted[start:] + struct.pack("<I", number), hashlib.sha512).digest()
            page = encrypted + digest
            plain = decrypt_page(page, number, key, salt)
            self.assertEqual(plain, (b"SQLite format 3\x00" if number == 1 else b"") + data + bytes(80))
            corrupt = bytearray(page)
            corrupt[100] ^= 1
            with self.assertRaisesRegex(ValueError, "HMAC"):
                decrypt_page(bytes(corrupt), number, key, salt)

    def test_invalid_copy_does_not_publish_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.db"
            raw.write_bytes(bytes(4096))
            output = root / "plain.db"
            with self.assertRaisesRegex(ValueError, "HMAC"):
                decrypt_copy(raw, output, bytes(32))
            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + ".pending").exists())


if __name__ == "__main__":
    unittest.main()
