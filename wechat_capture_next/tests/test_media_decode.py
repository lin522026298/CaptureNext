import importlib.util
import math
from pathlib import Path
import struct
import tempfile
import unittest
import wave
from wechat_capture_next import media_decode


class DecodeTests(unittest.TestCase):
    def test_strict_framing_rejects_truncation_and_empty_packet(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'voice.silk'
            for raw in (b'other',b'\x02#!SILK_V3',b'\x02#!SILK_V3\x05',b'\x02#!SILK_V3\x05\x00x',b'\x02#!SILK_V3\x00\x00'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):media_decode.silk_frames(path)
    @unittest.skipUnless(importlib.util.find_spec('pilk'),'optional native codec absent')
    def test_real_codec_synthetic_tone_roundtrip(self):
        import pilk
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);pcm=root/'tone.pcm';silk=root/'tone.silk';wav=root/'tone.wav'
            pcm.write_bytes(b''.join(struct.pack('<h',int(5000*math.sin(2*math.pi*440*i/24000))) for i in range(24000)))
            pilk.encode(str(pcm),str(silk),pcm_rate=24000,tencent=True)
            result=media_decode.decode(silk,wav)
            self.assertEqual(result['sample_rate'],24000)
            with wave.open(str(wav),'rb') as decoded:
                self.assertGreater(decoded.getnframes(),20000)
            self.assertFalse(wav.with_name(wav.name+'.decode.pcm').exists())


if __name__=='__main__':unittest.main()
