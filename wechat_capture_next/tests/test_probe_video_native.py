import base64
import hashlib
import unittest

from wechat_capture_next import probe_video_native as probe


class VideoWireProbeTests(unittest.TestCase):
    def test_wire_layout_has_redacted_headers_and_independent_4_8_path(self):
        blob=b'\x22\x22\x42\x20'+b'a'*32
        fields=list(probe.layout(blob))
        self.assertEqual([path for path,_ in fields],[(4,),(4,8)])
        self.assertEqual([field['header_hex'] for _,field in fields],['2222','4220'])
        self.assertTrue(all('61' not in field['header_hex'] for _,field in fields))

    def test_typed_bytes_integrity_is_required_before_layout(self):
        blob=b'\x22\x22\x42\x20'+b'a'*32
        value=dict(encoding='base64',byte_length=len(blob),sha256=hashlib.sha256(blob).hexdigest(),data=base64.b64encode(blob).decode())
        self.assertEqual(probe.typed_packed(dict(packed_info_data={'$wua_binary':value}))[0],blob)
        value['sha256']='f'*64
        with self.assertRaises(ValueError):probe.typed_packed(dict(packed_info_data={'$wua_binary':value}))


if __name__=='__main__':unittest.main()
