"""Offline bounded native video packed-field layout evidence, not association.

Protocol-reverse Phase 1/2: authenticate archived typed bytes, decode complete
protobuf wire framing without assigning an image schema, and compare complete
32-hex field values with actual VIDEO BASENAME identifiers, never directories.
No key, URL, message XML or payload hex is emitted. Evidence header_hex contains
only tag/length bytes, not field payload. Raw originals stay in the archive.
"""
import argparse
import base64
from collections import Counter, defaultdict
from contextlib import ExitStack, closing
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import time

from wechat_capture_v2.common import write_json_new,digest_file
from .compact_archive import CompactArchive
from .paths import local_absolute
from .state_guard import writer_lock
from .union_archive import cold_input,cold_reader

MAX_PACKED=1024**2


def wire_fields(data):
    if len(data)>MAX_PACKED:raise ValueError('oversized packed sample')
    offset=0;result=[]
    def varint():
        nonlocal offset
        value=0
        for shift in range(0,70,7):
            if offset>=len(data):raise ValueError('truncated wire varint')
            byte=data[offset];offset+=1
            if shift==63 and byte>1:raise ValueError('wire varint overflow')
            value|=(byte&127)<<shift
            if not byte&128:return value
        raise ValueError('oversized wire varint')
    while offset<len(data):
        start=offset;key=varint();number,wire=key>>3,key&7
        if not 0<number<2**29 or len(result)>=256:raise ValueError('wire field bounds')
        if wire==0:
            payload_start=offset;value=varint();length=offset-payload_start
        else:
            if wire==2:length=varint()
            elif wire in (1,5):length=8 if wire==1 else 4
            else:raise ValueError('unsupported wire type')
            payload_start=offset
            if offset+length>len(data):raise ValueError('truncated wire field')
            value=data[offset:offset+length];offset+=length
        result.append(dict(number=number,wire=wire,length=length,value=value,
            offset=start,header_hex=data[start:payload_start].hex()))
    return result


def typed_packed(raw):
    item=raw.get('packed_info_data')
    if item is None:return None
    if not isinstance(item,dict) or set(item)!={'$wua_binary'}:raise ValueError('unsupported packed representation')
    value=item['$wua_binary']
    if (value.get('encoding')!='base64' or type(value.get('byte_length')) is not int or
        not 0<=value['byte_length']<=MAX_PACKED or not isinstance(value.get('data'),str) or
        len(value['data'])>MAX_PACKED*4//3+16):raise ValueError('packed representation bounds')
    data=base64.b64decode(value['data'],validate=True)
    if len(data)!=value['byte_length'] or hashlib.sha256(data).hexdigest()!=value.get('sha256'):
        raise ValueError('packed byte SHA/length differs')
    return data,value['sha256']


def layout(data,*,depth=0,path=(),budget=None):
    if budget is None:budget=[0]
    fields=wire_fields(data)
    for field in fields:
        budget[0]+=1
        if budget[0]>1024:raise ValueError('nested field budget')
        current=(*path,field['number'])
        yield current,field
        if field['wire']==2 and field['length'] and depth<3:
            value=field['value']
            # A literal filename-token-shaped value is a leaf, not another
            # invented nested message. Unknown payloads retain unknown meaning.
            if re.fullmatch(rb'[0-9a-fA-F]{32}',value):continue
            try:
                nested=list(layout(value,depth=depth+1,path=current,budget=budget))
            except ValueError:
                continue
            yield from nested


def basename_index(archive,catalog):
    index=defaultdict(dict);metadata=Counter()
    for db,table,scope in ((archive._db,'next_union_asset_observation','union'),(catalog,'asset_history','state_history')):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():continue
        for path,sha,size in db.execute('SELECT relative_path,file_sha,bytes FROM '+table):
            name=PureWindowsPath(path).name.lower()
            if PureWindowsPath(name).suffix not in ('.mp4','.mkv','.mov','.m4v','.avi','.webm','.3gp'):continue
            metadata[scope+':video_extension_rows']+=1
            match=re.fullmatch(r'([0-9a-f]{32})(?:_[a-z0-9]+)*\.[a-z0-9]+',name)
            if not match:continue
            metadata[scope+':strict_basename_identifier_rows']+=1
            old=index[match[1]].setdefault(sha,dict(file_sha=sha,bytes=size,scopes=set()))
            if old['bytes']!=size:raise ValueError('video basename metadata lengths conflict')
            old['scopes'].add(scope)
    return index,metadata


def probe(restored,output,*,limit=5000):
    restored=local_absolute(restored);output=local_absolute(output)
    if output.exists() or output.is_relative_to(restored):raise ValueError('fresh independent private report required')
    state=restored/'state';union=restored/'union';started=time.monotonic()
    counts=Counter();shapes=Counter();matches=Counter();sources=Counter();examples=[];candidates=[];seen=set()
    with ExitStack() as stack:
        stack.enter_context(writer_lock(state));stack.enter_context(writer_lock(union))
        for path in (union/'archive.wua.sqlite',state/'catalog.sqlite'):
            stack.enter_context(cold_input(path))
        archive=stack.enter_context(CompactArchive(union/'archive.wua.sqlite',readonly=True,immutable=True))
        catalog=stack.enter_context(closing(cold_reader(state/'catalog.sqlite')))
        index,metadata=basename_index(archive,catalog)
        rows=archive._db.execute('''SELECT o.observation_id,o.raw_record_json,o.message_type,l.logical_id,s.source_id
            FROM observation_record o CROSS JOIN message_link l ON l.observation_id=o.observation_id
            CROSS JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id
            WHERE (CAST(o.message_type AS INTEGER)&4294967295) IN (43,62) ORDER BY o.rowid DESC LIMIT ?''',(limit,))
        for row in rows:
            counts['observations_sampled']+=1
            raw=json.loads(archive.pool.get_text(row['raw_record_json']))
            try:
                packed=typed_packed(raw)
                if packed is None:counts['packed_field_absent']+=1;continue
                data,packed_sha=packed;counts['typed_packed_SHA_length_verified']+=1;counts['packed_bytes']+=len(data)
                fields=list(layout(data));counts['complete_top_wire_layouts']+=1
            except (ValueError,TypeError,KeyError,AttributeError):
                counts['unsupported_packed_layout_or_integrity']+=1;continue
            source='source_sha256:'+hashlib.sha256(row['source_id'].encode()).hexdigest()[:16]
            sources[source]+=1
            for path,field in fields:
                path_text='.'.join(map(str,path));shape=path_text+':wire'+str(field['wire'])+':len'+str(field['length'])
                shapes[shape]+=1
                if len(examples)<20:
                    examples.append(dict(native_type=row['message_type'],packed_sha256=packed_sha,packed_bytes=len(data),
                        field_path=path_text,wire=field['wire'],payload_bytes=field['length'],
                        header_offset=field['offset'],header_hex=field['header_hex'],payload_redacted=True))
                value=field['value']
                if field['wire']!=2 or not isinstance(value,bytes) or not re.fullmatch(rb'[0-9a-fA-F]{32}',value):continue
                counts['literal_hex32_leaf_fields']+=1;token=value.decode('ascii').lower()
                if token not in index:continue
                matches[path_text]+=1;counts['native_token_basename_intersections']+=1
                key=(row['observation_id'],path_text,token)
                if key in seen:continue
                seen.add(key)
                candidates.append(dict(logical_id=row['logical_id'],observation_id=row['observation_id'],native_type=row['message_type'],
                    packed_sha256=packed_sha,packed_bytes=len(data),field_path=path_text,
                    token=token,content_md5_claim=False,
                    candidates=[dict(file_sha=item['file_sha'],bytes=item['bytes'],scopes=sorted(item['scopes'])) for item in index[token].values()]))
    result=dict(schema='next-native-video-layout-probe-1',scope='observed_wire_layout_and_actual_basename_intersection_not_message_association',
        elapsed_seconds=time.monotonic()-started,counts=dict(counts),metadata=dict(metadata),field_layout=dict(shapes),
        matching_field_paths=dict(matches),sources_hashed=dict(sources),redacted_wire_header_examples=examples,
        candidate_intersections_private=candidates,source_hashes=dict(probe=digest_file(Path(__file__))),
        writer_locks_cold_guards_and_connections_released=True,
        limitation='Field meanings unproven. Filename identifiers are not content MD5, native provenance, or duplicate-message identity. No bytes exported or decoded.')
    write_json_new(output,result)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restored',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--limit',type=int,default=5000);args=parser.parse_args(argv)
    value=probe(args.restored,args.out,limit=args.limit)
    print(json.dumps({key:value[key] for key in ('counts','metadata','matching_field_paths','elapsed_seconds',
        'writer_locks_cold_guards_and_connections_released')}),flush=True)


if __name__=='__main__':main()
