"""Short-lived synthetic UI fixture. No user source or authentication data."""
import json
from pathlib import Path
import sys
import threading
from contextlib import closing
import sqlite3
import struct
import hashlib
import io
import argparse
from unittest.mock import patch

from wechat_capture_next.tests.test_product import ProductTests
from wechat_capture_next.product import ProductCore
from wechat_capture_next.product_host import ProductHost
from wechat_capture_next.product_settings import DEFAULTS


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--video-fixture',type=Path)
    args=parser.parse_args()
    f=ProductTests('test_schedule_windows_and_settings_types');f.setUp()
    host=None
    try:
        f.prepared()
        # A real synthetic SILK packet exercises the exact CAS/worker/HTTP/audio
        # UI, not a mocked media URL. No user source is involved.
        import pilk
        from tests.test_wua_store import observation
        from wechat_capture_next.service import CaptureService
        from wechat_capture_next.compact_archive import CompactArchive
        from wechat_capture_next.viewer_media import import_voice
        from wechat_capture_v2.common import digest_file
        pcm=f.root/'ui-tone.pcm';silk=f.root/'ui-tone.silk';native=f.root/'ui-media.sqlite'
        pcm.write_bytes(struct.pack('<h',2000)*24000);pilk.encode(str(pcm),str(silk),pcm_rate=24000,tencent=True)
        with closing(sqlite3.connect(native)) as db:
            db.execute('CREATE TABLE Name2Id(user_name TEXT)');db.execute("INSERT INTO Name2Id VALUES('fixture-voice-room')")
            db.execute('CREATE TABLE VoiceInfo(chat_name_id,svr_id,create_time,voice_data BLOB)')
            db.execute('INSERT INTO VoiceInfo VALUES(1,424242,1767225600,?)',(silk.read_bytes(),));db.commit()
        with closing(CaptureService(f.state)) as service,CompactArchive(f.formal/'archive.wua.sqlite') as archive:
            from PIL import Image
            from wechat_capture_next.assets import configure_asset_root,capture_assets
            image=io.BytesIO();Image.new('RGB',(32,24),(40,140,160)).save(image,format='PNG')
            pixels=image.getvalue();md5=hashlib.md5(pixels).hexdigest()
            attach=Path(service.config['database_root']).parent/'msg'/'attach';attach.mkdir(parents=True)
            (attach/(md5+'.dat')).write_bytes(bytes(b^91 for b in pixels))
            document=b'synthetic safe file acceptance\n'
            (attach/'fixture-document.txt').write_bytes(document)
            video=None
            if args.video_fixture is not None:
                if args.video_fixture.stat().st_size>4*1024**2:raise ValueError('small synthetic video fixture required')
                video=args.video_fixture.read_bytes()
                if len(video)<16 or video[4:8]!=b'ftyp':raise ValueError('synthetic MP4 fixture required')
                (attach/(hashlib.md5(video).hexdigest()+'.mp4')).write_bytes(video)
            configure_asset_root(service,attach)
            capture_assets(service,'ui-image-synthetic')
            source=service.config['source_id'];account=service.config['account_alias']
            metadata=json.loads(archive._db.execute('SELECT metadata_json FROM source_device WHERE source_id=?',(source,)).fetchone()[0])
            observations=[
                observation(account_alias=account,conversation_id='fixture-voice-room',message_type='34',server_id='424242',
                    event_time='2026-01-01T00:00:00+00:00',body_text='合成语音播放验收'),
                observation(account_alias=account,conversation_id='fixture-image-room',message_type='3',server_id='424243',
                    native_locator=2,event_time='2026-01-01T00:00:01+00:00',body_text='<msg><img md5="'+md5+'"/></msg>'),
                observation(account_alias=account,conversation_id='fixture-file-room',message_type='49',server_id='424244',
                    native_locator=3,event_time='2026-01-01T00:00:02+00:00',body_text='<msg><appmsg><title>fixture-document.txt</title><type>6</type><appattach><filemd5>'+hashlib.md5(document).hexdigest()+'</filemd5><totallen>'+str(len(document))+'</totallen></appattach></appmsg></msg>')]
            if video is not None:observations.append(observation(account_alias=account,conversation_id='fixture-video-room',message_type='43',server_id='424245',
                native_locator=4,event_time='2026-01-01T00:00:03+00:00',body_text='<msg><videomsg md5="'+hashlib.md5(video).hexdigest()+'" length="'+str(len(video))+'"/></msg>'))
            archive.import_observations(metadata,dict(snapshot_id='ui-voice-synthetic',source_id=source),observations)
            import_voice(archive,service,source_id=source,account_alias=account,relative='message/media_0.db',
                capture_id='ui-synthetic-not-client',evidence=dict(plaintext=dict(sha256=digest_file(native))),path=native)
        with patch('wechat_capture_next.product.preferences.load',return_value=dict(DEFAULTS,auto_capture=False)):
            core=ProductCore(f.state,f.root/'product',union_root=f.formal,repository_root=f.state_repo,
                union_repository=f.union_repo)
        host=ProductHost(core)
        print(host.desktop[0].base_url,flush=True)
        for line in sys.stdin:
            if line.strip()=='quit':break
    finally:
        if host is not None:host.close()
        f.tearDown()


if __name__=='__main__':main()
