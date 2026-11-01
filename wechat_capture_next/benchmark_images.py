"""Bounded real image-view acceptance sample; no source writes or media export."""
import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from wechat_capture_v2.common import write_json_new
from .union_delivery import _offline
from .compact_archive import CompactArchive,HEAVY_CACHE_KIB
from .union_archive import cold_input
from .state_guard import writer_lock
from .image_media import ImageCache,candidates,hints,native_hints,load_keys


def retained_paths(archive,catalog,budget=32*1024**2):
    """Disposable bounded prefilter only; exact candidates still run normal checks.

    A checksum-token set avoids a SQLite full scan for each message whose
    checksum has no retained filename at all. Overflow disables the optimization,
    never truncates the candidate universe or changes an association.
    """
    tokens=set();size=0
    for db,table in ((archive._db,'next_union_asset_observation'),(catalog,'asset_history')):
        if db is None or db.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'",(table,)).fetchone() is None:continue
        for path, in db.execute('SELECT relative_path FROM '+table):
            # Preserve *every* possible 32-hex substring, including strings
            # embedded in longer hex basenames, matching candidates' LIKE.
            for match in re.finditer('[0-9a-f]{32,}',path.lower()):
                value=match.group()
                for offset in range(len(value)-31):
                    token=value[offset:offset+32]
                    if token in tokens:continue
                    size+=128  # conservative string + set-slot allowance
                    if size>budget:return None
                    tokens.add(token)
    return tokens


def sample_messages(archive,limit):
    """Prefer actual images over stickers, without conflating their formats."""
    for kind in (3,47):
        # Scan physical observations sequentially and filter before indexed
        # lookups. Logical-ID order otherwise thrashes the multi-GB source for
        # every non-image representative under the small default read cache.
        for logical, in archive._db.execute('''SELECT l.logical_id FROM observation_record o
            CROSS JOIN message_link m ON m.observation_id=o.observation_id
            CROSS JOIN logical_record l ON l.logical_id=m.logical_id
            WHERE (CAST(o.message_type AS INTEGER)&4294967295)=?
            AND l.representative_observation_id=o.observation_id ORDER BY o.rowid LIMIT ?''',(kind,limit)):
            yield logical,kind


def wire_layout(data):
    """Strict top-level protobuf wire layout, no guessed field semantics."""
    offset=0;fields=[]
    def varint():
        nonlocal offset
        value=0
        for shift in range(0,70,7):
            if offset>=len(data):raise ValueError('truncated varint')
            byte=data[offset];offset+=1;value|=(byte&127)<<shift
            if not byte&128:return value
        raise ValueError('oversized varint')
    while offset<len(data):
        key=varint();number,wire=key>>3,key&7
        if not 0<number<2**29 or len(fields)>=256:raise ValueError('invalid field count/number')
        if wire==0:varint();length=0
        elif wire in (1,5):length=8 if wire==1 else 4;offset+=length
        elif wire==2:length=varint();offset+=length
        else:raise ValueError('unsupported wire type')
        if offset>len(data):raise ValueError('truncated field')
        fields.append((number,wire,length))
    return fields


def diagnose_images(archive,service,cache,limit):
    """No message linking: isolate XML, retained naming and actual asset decode."""
    from .union_assets import _blocks
    tokens=retained_paths(archive,service.catalog.db);counts=Counter();layout=Counter();packed=Counter();assets=[]
    for logical,kind in sample_messages(archive,limit):
        if kind!=3:break
        claims,unsupported=hints(archive,logical);counts['type3_eligible']+=1
        counts['type3_explicit_hint_messages']+=bool(claims);counts['explicit_claims']+=len(claims)
        counts['unsupported_xml_observations']+=unsupported
        if tokens is not None:counts['messages_with_retained_path_token_intersection']+=any(c['md5'] in tokens for c in claims)
    # At most 100 packed records per source: structural evidence, never links.
    for source, in archive._db.execute('SELECT source_id FROM source_device'):
        for raw_id, in archive._db.execute('''SELECT o.raw_record_json FROM observation_record o
            JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id WHERE s.source_id=?
            AND (CAST(o.message_type AS INTEGER)&4294967295)=3 LIMIT 100''',(source,)):
            raw=json.loads(archive.pool.get_text(raw_id));value=raw.get('packed_info_data',{}).get('$wua_binary')
            if not value:packed['not_binary']+=1;continue
            blob=base64.b64decode(value['data'],validate=True)
            if len(blob)!=value['byte_length'] or hashlib.sha256(blob).hexdigest()!=value['sha256']:raise ValueError('packed archive binary readback differs')
            packed['samples']+=1;packed['bytes']+=len(blob)
            if len(blob)>1024**2:packed['oversized_not_parsed']+=1;continue
            try:
                for number,wire,length in wire_layout(blob):layout[str(number)+':wire'+str(wire)+':bytes'+str(length)]+=1
                packed['wire_framing_valid']+=1
            except ValueError:packed['wire_framing_unproven']+=1
            found={m.decode('ascii').lower() for m in re.findall(rb'[0-9a-fA-F]{32}',blob)}
            packed['ascii_hex_tokens']+=len(found)
            if tokens is not None:packed['retained_path_token_intersections']+=len(found&tokens)
    # This is explicitly independent asset decode, NOT a message candidate.
    for sha,size,path in archive._db.execute('''SELECT file_sha,min(bytes),min(relative_path)
        FROM next_union_asset_observation WHERE lower(relative_path) LIKE '%.dat'
        GROUP BY file_sha ORDER BY file_sha LIMIT 20'''):
        if not 0<size<=64*1024**2:continue
        raw=b''.join(block for *_,block in _blocks(service.objects.db,sha,size))
        if not raw.startswith(bytes.fromhex('070856320807')):continue
        command=[sys.executable,'-m','wechat_capture_next.media_decode']
        request=dict(kind='image_bytes',data=base64.b64encode(raw).decode('ascii'),
            candidates=[dict(aes_hex=c.key.hex(),xor_byte=c.xor_byte) for c in cache.candidates])
        response=subprocess.run(command,input=json.dumps(request),text=True,capture_output=True,timeout=60,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if response.returncode:counts['asset_decode_unsupported']+=1;continue
        decoded=json.loads(response.stdout);data=base64.b64decode(decoded['data'],validate=True);metadata=decoded['image']
        if hashlib.sha256(data).hexdigest()!=metadata['sha256'] or hashlib.md5(data).hexdigest()!=metadata['md5']:raise ValueError('asset image worker readback differs')
        assets.append(dict(raw_sha=sha,raw_bytes=size,example_path=path,image=metadata,decoded_bytes=len(data),message_association='unknown_not_attempted'))
        if len(assets)>=5:break
    return dict(scope='bounded_native_image_diagnostic_not_message_association_acceptance',counts=dict(counts),
        retained_path_tokens=len(tokens) if tokens is not None else None,packed_structure=dict(packed),packed_wire_layout=dict(layout),
        actual_assets_private=assets,actual_asset_decode_successes=len(assets),plaintext_preview_files_created=0,
        lifetime_readonly_guards=True,source_files_written=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('state','union','out'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--keyring',type=Path)
    p.add_argument('--message-limit',type=int,default=10000,help='sample bound per message kind, not an acquisition limit')
    p.add_argument('--attempt-limit',type=int,default=100,help='unique original objects to test')
    p.add_argument('--success-target',type=int,default=5)
    p.add_argument('--diagnose-images',action='store_true',help='separate native-layout and independent asset decode proof, never message association');a=p.parse_args(argv)
    if min(a.message_limit,a.attempt_limit,a.success_target)<=0:p.error('sample limits must be positive')
    from .paths import local_absolute
    a.state=local_absolute(a.state,allow_relative=True);a.union=local_absolute(a.union,allow_relative=True);a.out=local_absolute(a.out,allow_relative=True)
    if a.out.exists():raise FileExistsError('fresh aggregate receipt required')
    start=time.monotonic();cache=ImageCache();counts=Counter();methods=Counter();formats=Counter();diagnostic=[];successes=[];seen=set();matched_messages=set()
    if a.keyring:load_keys(cache,local_absolute(a.keyring,allow_relative=True))
    with writer_lock(a.state),writer_lock(a.union),_offline(a.state) as service,cold_input(a.union/'archive.wua.sqlite'),\
         CompactArchive(a.union/'archive.wua.sqlite',readonly=True,immutable=True) as archive:
        archive._db.execute(f'PRAGMA cache_size=-{HEAVY_CACHE_KIB}')
        if a.diagnose_images:
            result=diagnose_images(archive,service,cache,a.message_limit);cache.clear()
            result.update(elapsed_seconds=time.monotonic()-start,preview_RAM_bytes_after_clear=cache.bytes)
            write_json_new(a.out,result);print(json.dumps({k:v for k,v in result.items() if not k.endswith('_private')}));return
        paths=retained_paths(archive,service.catalog.db)
        for logical,kind in sample_messages(archive,a.message_limit):
            counts['messages_sampled']+=1
            counts['messages_sampled_type:'+str(kind)]+=1;after=''
            claims,unsupported=hints(archive,logical)
            native,native_unsupported=native_hints(archive,logical)
            counts['explicit_checksum_messages_type:'+str(kind)]+=bool(claims)
            counts['unsupported_xml_observations']+=unsupported
            counts['native_filename_hint_messages_type:'+str(kind)]+=bool(native)
            counts['unsupported_native_observations']+=native_unsupported
            if paths is not None and not (any(claim['md5'] in paths for claim in claims) or any(claim['token'] in paths for claim in native)):
                counts['no_retained_path_checksum_prefilter']+=1;continue
            while True:
                page=candidates(archive,service.catalog.db,logical,after=after);counts['candidate_objects_in_sampled_pages']+=len(page['rows'])
                for item in page['rows']:
                    if item['file_sha'] in seen:counts['duplicate_originals_skipped']+=1;continue
                    if counts['attempts']>=a.attempt_limit:break
                    if not item['md5s']:counts['candidate_without_xml_checksum_for_view_contract']+=1;continue
                    seen.add(item['file_sha']);counts['attempts']+=1;counts['attempts_type:'+str(kind)]+=1
                    try:
                        result=cache.prepare(archive,service.catalog.db,service.objects.db,logical_id=logical,sha=item['file_sha'],expected_md5=item['md5s'][0])
                        if result['status']=='ready':
                            if not result['content_checksum_matches'] and result['matching_content_checksum_fields']:
                                result=cache.prepare(archive,service.catalog.db,service.objects.db,logical_id=logical,
                                    sha=item['file_sha'],expected_md5=result['matching_content_checksum_fields'][0]['md5'])
                            binary=cache.read(result['artifact_id']);counts['ready']+=1;counts['checksum_matches']+=int(result['content_checksum_matches'])
                            if result['content_checksum_matches']:matched_messages.add(logical)
                            counts['checksum_matched_messages']=len(matched_messages)
                            methods[result['image']['method']]+=1;formats[result['image']['format']]+=1
                            if not binary.data:raise ValueError('empty actual image view')
                            successes.append(dict(message_type=kind,logical_id=logical,raw_sha=item['file_sha'],image=result['image'],
                                content_checksum_matches=result['content_checksum_matches'],candidate_evidence=item['evidence'],
                                explicit_xml_checksum_fields=page['hints'],native_filename_hints=page['native_filename_hints'],
                                binary_response_bytes=len(binary.data),mime=binary.content_type))
                        else:
                            counts[result['status']]+=1
                            counts['reason:'+result.get('decoder_error_type',result.get('reason','unknown'))]+=1
                            counts['container:'+result.get('raw_container','unknown')]+=1
                            if len(diagnostic)<5:
                                from .union_assets import _blocks
                                first=next(_blocks(service.objects.db,item['file_sha'],item['bytes']))[-1]
                                diagnostic.append(dict(prefix_hex=first[:12].hex(),bytes=item['bytes'],candidate_evidence=item['evidence']))
                    except Exception as error:counts['error:'+type(error).__name__]+=1
                    if counts['checksum_matched_messages']>=a.success_target:break
                if counts['checksum_matched_messages']>=a.success_target or counts['attempts']>=a.attempt_limit or page['next_after'] is None:break
                after=page['next_after']
            if counts['checksum_matched_messages']>=a.success_target or counts['attempts']>=a.attempt_limit:break
    result=dict(scope='bounded_functional_sample_not_full_media_coverage',counts=dict(counts),methods=dict(methods),formats=dict(formats),
        lifetime_readonly_guards=True,source_files_written=False,plaintext_preview_files_created=0,
        loaded_candidate_keys=len(cache.candidates),preview_RAM_bytes=cache.bytes,elapsed_seconds=time.monotonic()-start,
        sample_limits=dict(messages_per_kind=a.message_limit,unique_originals=a.attempt_limit,success_target=a.success_target),
        diagnostic_private=diagnostic,successes_private=successes)
    cache.clear();result['preview_RAM_bytes_after_clear']=cache.bytes
    write_json_new(a.out,result);print(json.dumps({k:v for k,v in result.items() if not k.endswith('_private')}))


if __name__=='__main__':main()
