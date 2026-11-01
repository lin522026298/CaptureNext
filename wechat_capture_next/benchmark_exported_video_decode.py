"""Offline full decode-to-null QA of already owned, hash-verified video exports.

Uses explicit installed FFmpeg tools, never launches an attachment or player.
Only the MOV/MP4 demuxer and local file/pipe protocols are allowed. Stream/format
fields are whitelisted; embedded text metadata is not copied into the receipt.
No media derivatives are written. This does not verify browser/product playback.
"""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import time

from wechat_capture_v2.common import digest_file,write_json_new
from .paths import local_absolute
from .union_archive import cold_input


def verify(receipt,out,ffprobe,ffmpeg):
    receipt=local_absolute(receipt);out=local_absolute(out)
    ffprobe=local_absolute(ffprobe);ffmpeg=local_absolute(ffmpeg)
    if out.exists() or out in (receipt,ffprobe,ffmpeg):raise ValueError('fresh video decode receipt required')
    value=json.loads(receipt.read_text(encoding='utf-8'));rows=[];started=time.monotonic()
    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)
    with ExitStack() as stack:
        stack.enter_context(cold_input(receipt))
        for item in value['exports_private']:
            if item['kind']!='video':continue
            path=local_absolute(receipt.parent/item['relative_output'])
            if path.parent!=receipt.parent:raise ValueError('export is not an owned QA child')
            stack.enter_context(cold_input(path))
            if path.stat().st_size!=item['bytes'] or digest_file(path)!=item['file_sha']:
                raise ValueError('owned video export differs from authenticated QA receipt')
            probe=subprocess.run([str(ffprobe),'-v','error','-protocol_whitelist','file,pipe',
                '-format_whitelist','mov','-show_entries',
                'stream=index,codec_name,codec_type,width,height,duration,nb_frames:format=format_name,duration,size',
                '-of','json',str(path)],capture_output=True,text=True,timeout=90,creationflags=creationflags)
            row=dict(file_sha=item['file_sha'],bytes=item['bytes'],relative_output=item['relative_output'],
                probe_exit=probe.returncode,full_decode_exit=None,full_decode_to_null_verified=False)
            if probe.returncode==0:
                metadata=json.loads(probe.stdout)
                row.update(streams=metadata.get('streams',[]),format=metadata.get('format',{}))
                decoded=subprocess.run([str(ffmpeg),'-hide_banner','-nostdin','-v','error','-xerror',
                    '-protocol_whitelist','file,pipe','-format_whitelist','mov','-threads','2','-i',str(path),
                    '-map','0:v:0','-map','0:a?','-sn','-dn','-f','null','-'],
                    capture_output=True,text=True,timeout=90,creationflags=creationflags)
                row['full_decode_exit']=decoded.returncode;row['full_decode_to_null_verified']=decoded.returncode==0
                row['decoder_error_present']=bool(decoded.stderr.strip())
            if digest_file(path)!=item['file_sha']:raise ValueError('decode changed owned original')
            row.update(original_unchanged=True,browser_playback_verified=False,product_playback_verified=False)
            rows.append(row)
    result=dict(schema='next-owned-export-video-decode-QA-1',rows=rows,elapsed_seconds=time.monotonic()-started,
        successful_full_decodes=sum(row['full_decode_to_null_verified'] for row in rows),
        tools_sha256=dict(ffprobe=digest_file(ffprobe),ffmpeg=digest_file(ffmpeg)),
        tool_version_scope='explicit_installed_tool_paths',demuxer_whitelist=['mov'],protocol_whitelist=['file','pipe'],
        no_UI_or_attachment_execution=True,no_media_derivatives_written=True,
        all_cold_guards_released=True,browser_product_playback_verified=False,
        limitation='Full local decoder readback proves these exports decode in the explicit FFmpeg build; it does not prove all videos or product/browser playback.')
    write_json_new(out,result);return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('receipt','out','ffprobe','ffmpeg'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(argv);result=verify(args.receipt,args.out,args.ffprobe,args.ffmpeg)
    print(json.dumps({key:result[key] for key in ('successful_full_decodes','elapsed_seconds','all_cold_guards_released',
        'browser_product_playback_verified')}))


if __name__=='__main__':main()
