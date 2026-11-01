"""Disposable native-code decoder worker; never opens state or client keys."""
import json
import base64
import hashlib
from pathlib import Path
import shutil
import sys
import wave

RATE=24000
MAX_PCM=96*1024*1024  # preview bound only; the archived original is never truncated


def silk_frames(path):
    with path.open('rb') as stream:
        head=stream.read(10)
        if head==b'\x02#!SILK_V3':pass
        elif head[:9]==b'#!SILK_V3':stream.seek(9)
        else:raise ValueError('unsupported saved voice codec')
        count=0
        while True:
            raw=stream.read(2)
            if not raw:break
            if len(raw)!=2:raise ValueError('truncated SILK framing')
            size=int.from_bytes(raw,'little')
            if size==65535:
                if stream.read(1):raise ValueError('SILK trailing bytes')
                break
            if not 0<size<=5120 or len(stream.read(size))!=size:raise ValueError('invalid SILK frame')
            count+=1
            # SILK packets can contain up to five 20 ms frames. This is an
            # upper bound, not a claimed duration from a buggy packet parser.
            if count*RATE*2//10>MAX_PCM:raise ValueError('voice preview too large; original preserved')
    if not count:raise ValueError('empty SILK voice')
    return count


def decode(source,target):
    import pilk
    source=Path(source);target=Path(target)
    if target.exists():raise FileExistsError('fresh decoder target required')
    silk_frames(source)
    pcm=target.with_name(target.name+'.decode.pcm')
    if pcm.exists():raise FileExistsError('fresh PCM path required')
    try:
        pilk.decode(str(source),str(pcm),pcm_rate=RATE)
        size=pcm.stat().st_size
        if not 0<size<=MAX_PCM or size%2:raise ValueError('decoded PCM shape invalid')
        with pcm.open('rb') as raw,wave.open(str(target),'wb') as out:
            out.setparams((1,2,RATE,0,'NONE','not compressed'))
            while block:=raw.read(256*1024):out.writeframesraw(block)
        with wave.open(str(target),'rb') as check:
            if (check.getnchannels(),check.getsampwidth(),check.getframerate(),check.getnframes())!=(1,2,RATE,size//2):
                raise ValueError('decoded WAVE readback differs')
        return dict(codec='pilk-0.2.4',sample_rate=RATE,channels=1,sample_bytes=2,frames=size//2)
    finally:
        if pcm.exists():pcm.unlink()


def main():
    try:
        request=json.loads(sys.stdin.read())
        if request.get('kind')=='image_bytes':
            if set(request)!={'kind','data','candidates'}:raise ValueError('image request invalid')
            from tools.decode_weixin_dat import decode as decode_image,Candidate,MAX_BYTES
            if not isinstance(request['data'],str) or len(request['data'])>MAX_BYTES*4//3+16:raise ValueError('image preview too large')
            raw=base64.b64decode(request['data'],validate=True)
            candidates=tuple(Candidate(bytes.fromhex(r['aes_hex']),r['xor_byte']) for r in request['candidates'])
            image=decode_image(raw,candidates)
            if image.image_format not in ('PNG','JPEG','GIF','WEBP'):raise ValueError('saved image format not supported by browser viewer')
            result=dict(image=dict(format=image.image_format,dimensions=image.dimensions,frames=image.frames,method=image.method,
                sha256=hashlib.sha256(image.data).hexdigest(),md5=hashlib.md5(image.data).hexdigest()),data=base64.b64encode(image.data).decode('ascii'))
            print(json.dumps(result));return 0
        if set(request)!={'source','target'}:raise ValueError('decoder request invalid')
        result=decode(request['source'],request['target']);print(json.dumps(result));return 0
    except Exception as error:
        print(json.dumps(dict(error_type=type(error).__name__,status='saved_decode_failed')));return 1


if __name__=='__main__':raise SystemExit(main())
