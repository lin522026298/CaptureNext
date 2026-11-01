from io import BytesIO
import hashlib
import struct
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image
from tools.decode_weixin_dat import (Candidate, DecodeError, V1_KEY, V1_MAGIC, V2_MAGIC,
                                     decode, decrypt_envelope, derive_v2_key)


def envelope(plain, key, xor, prefix, tail, magic=V2_MAGIC):
    head=magic+struct.pack('<II',prefix,tail)+b'\0'
    pad=16-prefix%16
    enc=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    cipher=enc.update(plain[:prefix]+bytes([pad])*pad)+enc.finalize()
    end=len(plain)-tail
    return head+cipher+plain[prefix:end]+bytes(b^xor for b in plain[end:])


class DatTests(unittest.TestCase):
    def setUp(self):
        data=BytesIO()
        Image.new('RGB',(8,7),(20,50,90)).save(data,format='PNG')
        self.png=data.getvalue()
        self.candidate=Candidate(bytes(range(16)),0x79,'synthetic')

    def test_formula_is_ascii_not_hex_decode(self):
        candidate=derive_v2_key(123456,'synthetic_user')
        expected=hashlib.md5(b'123456synthetic_user').hexdigest()[:16].encode()
        self.assertEqual(candidate.key,expected)
        self.assertEqual(len(candidate.key),16)
        self.assertEqual(candidate.xor_byte,123456&255)

    def test_bad_code_rejected(self):
        for code in (-1,2**32,True):
            with self.assertRaises(ValueError):
                derive_v2_key(code,'test')

    def test_legacy_xor_and_plain(self):
        for xor in (0,0xFB,0x79):
            result=decode(bytes(b^xor for b in self.png))
            self.assertEqual(result.data,self.png)
            self.assertEqual(result.dimensions,(8,7))

    def test_v2_aligned_and_unaligned(self):
        for prefix in (0,1,16,17,32):
            for tail in (0,5):
                blob=envelope(self.png,self.candidate.key,0x79,prefix,tail)
                self.assertEqual(decode(blob,(self.candidate,)).data,self.png)

    def test_wrong_key_rejected(self):
        blob=envelope(self.png,self.candidate.key,0x79,32,5)
        with self.assertRaises(DecodeError):
            decode(blob,(Candidate(b'x'*16,0x79),))

    def test_wrong_xor_rejected_by_image_parser(self):
        blob=envelope(self.png,self.candidate.key,0x79,32,12)
        with self.assertRaises(DecodeError):
            decode(blob,(Candidate(self.candidate.key,0),))

    def test_header_length_overflow_rejected(self):
        blob=V2_MAGIC+struct.pack('<II',0xFFFFFFFF,0)+b'\0'+b'x'*16
        with self.assertRaises(DecodeError):
            decrypt_envelope(blob,self.candidate.key,0)

    def test_truncation_rejected(self):
        blob=envelope(self.png,self.candidate.key,0x79,32,5)
        with self.assertRaises(DecodeError):
            decode(blob[:40],(self.candidate,))

    def test_magic_only_is_not_an_image(self):
        with self.assertRaises(DecodeError):
            decode(b'\x89PNG\r\n\x1a\n'+b'x'*20)

    def test_v1_fixed_key_no_tail(self):
        blob=envelope(self.png,V1_KEY,0,17,0,V1_MAGIC)
        self.assertEqual(decode(blob).data,self.png)

    def test_unknown_and_empty_rejected(self):
        for blob in (b'',b'nothing here',V2_MAGIC):
            with self.assertRaises(DecodeError):
                decode(blob)


if __name__=='__main__':
    unittest.main()
