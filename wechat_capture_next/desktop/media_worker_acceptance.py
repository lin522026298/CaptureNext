"""Synthetic V2 image and SILK acceptance against the frozen decoder worker."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import time
import wave

from wechat_capture_v2.common import digest_file,write_json_new


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--exe',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args(argv)
    a.out.mkdir(parents=True,exist_ok=False);exe=a.exe.resolve();started=time.monotonic()
    def worker(request):
        run=subprocess.run([str(exe),'--media-worker'],input=json.dumps(request),text=True,
            capture_output=True,timeout=60,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if run.returncode:raise ValueError('frozen decoder failed: '+str(run.returncode))
        return json.loads(run.stdout)
    from PIL import Image
    from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
    from tools.decode_weixin_dat import V2_MAGIC
    image=io.BytesIO();Image.new('RGB',(32,24),(20,130,140)).save(image,format='PNG');plain=image.getvalue()
    key=b'synthetic-key-16';cipher=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    blob=V2_MAGIC+struct.pack('<II',16,len(plain)-16)+b'\x01'+cipher.update(plain[:16]+bytes([16])*16)+cipher.finalize()+bytes(b^91 for b in plain[16:])
    response=worker(dict(kind='image_bytes',data=base64.b64encode(blob).decode(),candidates=[dict(aes_hex=key.hex(),xor_byte=91)]))
    decoded=base64.b64decode(response['data'],validate=True)
    if decoded!=plain or response['image']['sha256']!=hashlib.sha256(plain).hexdigest():raise ValueError('frozen image readback differs')
    import pilk
    pcm=a.out/'synthetic.pcm';silk=a.out/'synthetic.silk';wav=a.out/'synthetic.wav'
    pcm.write_bytes(struct.pack('<h',2000)*24000);pilk.encode(str(pcm),str(silk),pcm_rate=24000,tencent=True)
    voice=worker(dict(source=str(silk.resolve()),target=str(wav.resolve())))
    with wave.open(str(wav),'rb') as file:
        shape=(file.getnchannels(),file.getsampwidth(),file.getframerate(),file.getnframes())
        if shape!=(1,2,24000,24000) or len(file.readframes(24001))!=48000:raise ValueError('frozen voice readback differs')
    write_json_new(a.out/'RESULT.private.json',dict(pass_all=True,synthetic=True,executable_sha256=digest_file(exe),
        elapsed_seconds=time.monotonic()-started,image=response['image'],image_bytes_equal=True,voice=voice,
        wave_full_readback=True,physical_disk_write_bytes=None,not_real_history_coverage=True))
    print(json.dumps(dict(pass_all=True,image_format=response['image']['format'],voice_frames=voice['frames'])))


if __name__=='__main__':main()
