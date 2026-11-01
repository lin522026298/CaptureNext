"""Explicit message checksum candidates and disposable in-memory image views.

Filename matches are candidates, not native message/file linkage. Pixel-checked
decoded bytes may confirm content checksum equality, never dedupe messages or
prove which physical device path supplied the original. No network fetches.
"""
import base64
from collections import OrderedDict
from contextlib import closing
import hashlib
import heapq
import itertools
import json
from pathlib import Path
import re
import subprocess
import sys
import threading

from defusedxml import ElementTree as XML
from wechat_capture_v2.common import canonical
from .media_preview import BinaryMedia
from .union_assets import _blocks

MAX_IMAGE=64*1024**2
IMAGE_CODEC='validated-dat-image-1'
MIMES={'PNG':'image/png','JPEG':'image/jpeg','GIF':'image/gif','WEBP':'image/webp'}


def load_keys(cache,path):
    from .assets import _parents,_file
    from tools.decode_weixin_dat import load_candidates
    path=Path(path);path=_parents(path.parent)/path.name;_file(path)
    if path.stat().st_size>1024**2:raise ValueError('oversized supplied image parameters')
    values=load_candidates(path)
    if any(len(c.key)!=16 or type(c.xor_byte) is not int or not 0<=c.xor_byte<=255 for c in values):raise ValueError('invalid supplied image parameters')
    cache.candidates=values
    return dict(loaded_candidates=len(values),scope='runtime_memory_only',state_and_restore_unchanged=True,
        note='Keep the original private key file separately for future offline decoding; already decoded previews are disposable.')


def hints(archive,logical_id):
    result=[];unsupported=0
    for row in archive._db.execute('''SELECT o.observation_id,o.body_text FROM message_link l
        JOIN observation_record o ON o.observation_id=l.observation_id WHERE l.logical_id=?''',(logical_id,)):
        if row['body_text'] is None:continue
        body=archive.pool.get_text(row['body_text']);start=body.find('<msg')
        if start<0:continue
        if len(body)>4*1024**2:unsupported+=1;continue
        try:root=XML.fromstring(body[start:])
        except Exception:unsupported+=1;continue
        for element in root.iter():
            tag=element.tag.rsplit('}',1)[-1]
            allowed={'img':('md5','originsourcemd5','cdnthumbmd5'),'emoji':('md5',),'videomsg':('cdnthumbmd5',)}.get(tag,())
            for field in allowed:
                value=element.attrib.get(field,'')
                if not re.fullmatch('[0-9a-fA-F]{32}',value) or value=='0'*32:continue
                result.append(dict(observation_id=row['observation_id'],field=tag+'.'+field,md5=value.lower(),
                    role='thumbnail' if field=='cdnthumbmd5' else 'original' if field=='originsourcemd5' else 'image'))
    return result,unsupported


def protobuf_fields(data):
    """Bounded wire parser only; unknown fields remain uninterpreted."""
    if len(data)>1024**2:raise ValueError('native media field exceeds preview parser bound')
    offset=0;fields=[];seen=set()
    def varint():
        nonlocal offset
        value=0
        for shift in range(0,70,7):
            if offset>=len(data):raise ValueError('truncated native varint')
            byte=data[offset];offset+=1
            if shift==63 and byte>1:raise ValueError('overflowing native varint')
            value|=(byte&127)<<shift
            if not byte&128:return value
        raise ValueError('oversized native varint')
    while offset<len(data):
        key=varint();number,wire=key>>3,key&7
        if not 0<number<2**29 or number in seen or len(fields)>=256:raise ValueError('duplicate or invalid native field')
        seen.add(number)
        if wire==0:value=varint()
        else:
            if wire==2:size=varint()
            elif wire in (1,5):size=8 if wire==1 else 4
            else:raise ValueError('unsupported native wire type')
            if offset+size>len(data):raise ValueError('truncated native field')
            value=data[offset:offset+size];offset+=size
        fields.append((number,wire,value))
    return fields


def native_hints(archive,logical_id):
    """Observed packed_info_data field 3 -> field 4 filename identifier.

    This 32-hex token is *not* asserted to be an image-content MD5. Matching
    filenames yields candidates only; XML content checksums are independent.
    Unknown well-framed fields are retained in raw provenance and not assigned
    meanings; duplicates, truncation or unexpected identifier shape yield none.
    """
    result=[];unsupported=0
    for row in archive._db.execute('''SELECT o.observation_id,o.raw_record_json FROM message_link l
        JOIN observation_record o ON o.observation_id=l.observation_id WHERE l.logical_id=?
        AND (CAST(o.message_type AS INTEGER)&4294967295)=3''',(logical_id,)):
        try:
            raw=json.loads(archive.pool.get_text(row['raw_record_json']))
            item=raw.get('packed_info_data')
            if item is None:continue
            if not isinstance(item,dict) or set(item)!={'$wua_binary'}:raise ValueError('unsupported native binary representation')
            value=item['$wua_binary']
            if (value.get('encoding')!='base64' or type(value.get('byte_length')) is not int or
                not 0<=value['byte_length']<=1024**2 or not isinstance(value.get('data'),str) or
                len(value['data'])>1024**2*4//3+16):raise ValueError('invalid native binary shape')
            blob=base64.b64decode(value['data'],validate=True)
            if len(blob)!=value['byte_length'] or hashlib.sha256(blob).hexdigest()!=value.get('sha256'):raise ValueError('native binary integrity differs')
            fields=protobuf_fields(blob);parents=[v for n,w,v in fields if n==3 and w==2]
            if any(n==3 and w!=2 for n,w,_ in fields):raise ValueError('unexpected native identifier parent wire')
            if not parents:continue
            nested=protobuf_fields(parents[0]);identifiers=[v for n,w,v in nested if n==4 and w==2]
            if any(n==4 and w!=2 for n,w,_ in nested):raise ValueError('unexpected native identifier wire')
            if not identifiers:continue
            token=identifiers[0].decode('ascii')
            if not re.fullmatch('[0-9a-fA-F]{32}',token) or token=='0'*32:raise ValueError('invalid native filename identifier')
            result.append(dict(observation_id=row['observation_id'],field='raw_record.packed_info_data.protobuf.3.4',
                token=token.lower(),identifier_kind='native_filename_identifier_candidate',
                packed_sha256=value['sha256'],content_md5_claim=False,semantics='observed_filename_token_not_confirmed_native_schema'))
        except (ValueError,TypeError,KeyError,AttributeError,UnicodeError):unsupported+=1
    return result,unsupported


def candidates(archive,catalog,logical_id,*,after='',selected_sha=None,expected_md5=None,limit=50):
    if after and not re.fullmatch('[0-9a-f]{64}',after):raise ValueError('invalid image candidate cursor')
    if selected_sha is not None and not re.fullmatch('[0-9a-f]{64}',selected_sha):raise ValueError('invalid original hash')
    claims,unsupported=hints(archive,logical_id);checksums=sorted({c['md5'] for c in claims})
    native,native_unsupported=native_hints(archive,logical_id)
    if expected_md5 is not None:
        if expected_md5 not in checksums:raise ValueError('checksum is not an explicit field of this message')
        checksums=[expected_md5]
    streams=[]
    lookups=[(md5,'explicit_xml_content_md5') for md5 in checksums]+[(token,'native_filename_identifier_candidate') for token in sorted({c['token'] for c in native})]
    for token,kind in lookups:
        for db,table,origin in ((archive._db,'next_union_asset_observation','retained_union'),(catalog,'asset_history','current_state_history')):
            if db is None or db.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'",(table,)).fetchone() is None:continue
            where='lower(relative_path) LIKE ? AND file_sha>?';args=['%'+token+'%',after]
            if selected_sha is not None:where+=' AND file_sha=?';args.append(selected_sha)
            cursor=db.execute(('SELECT file_sha,bytes,relative_path FROM ' if kind=='native_filename_identifier_candidate' else
                'SELECT file_sha,min(bytes),count(*),min(relative_path) FROM ')+table+' WHERE '+where+
                (' ORDER BY file_sha' if kind=='native_filename_identifier_candidate' else ' GROUP BY file_sha ORDER BY file_sha'),args)
            def stream(cursor=cursor,token=token,kind=kind,origin=origin):
                if kind=='native_filename_identifier_candidate':
                    def filenames():
                        # Only a basename identifier, never a conversation
                        # directory hash or arbitrary substring in a path.
                        pattern=re.compile(re.escape(token)+r'(?:_[a-z0-9]+)*(?:\.[a-z0-9]+)?')
                        for sha,group in itertools.groupby(cursor,key=lambda r:r[0]):
                            example=None;first_size=None;count=0
                            for _,size,path in group:
                                name=path.replace('\\','/').rsplit('/',1)[-1].lower()
                                if not pattern.fullmatch(name):continue
                                if count and size!=first_size:raise ValueError('native image candidate lengths conflict')
                                count+=1;first_size=size;example=path if example is None or path<example else example
                            if count:yield sha,first_size,count,example
                    rows=filenames()
                else:rows=cursor
                for sha,size,count,path in rows:
                    evidence=dict(identifier_kind=kind,token=token,scope=origin,bytes=size,metadata_rows=count,example_path=path)
                    if kind=='explicit_xml_content_md5':evidence['md5']=token
                    yield sha,evidence
            streams.append(stream())
    rows=[];more=False
    merged=heapq.merge(*streams,key=lambda r:r[0])
    for sha,group in itertools.groupby(merged,key=lambda r:r[0]):
        evidence=[v for _,v in group]
        if len({v['bytes'] for v in evidence})!=1:raise ValueError('image candidate lengths conflict')
        if len(rows)==limit:more=True;break
        rows.append(dict(file_sha=sha,bytes=evidence[0]['bytes'],status='candidate',
            md5s=sorted(set(checksums) if any(v['identifier_kind']=='native_filename_identifier_candidate' for v in evidence) else {v['md5'] for v in evidence}),evidence=evidence,
            origin_link_confirmed=False,matching_basis='explicit_message_content_md5_or_native_packed_filename_token_not_time'))
    return dict(status='candidate' if rows else 'association_unknown',rows=rows,hints=claims,native_filename_hints=native,
        unsupported_xml_observations=unsupported,unsupported_native_observations=native_unsupported,next_after=rows[-1]['file_sha'] if more else None,
        scope='all_retained_candidates_paginated_not_acquisition_limit',
        limitation='No filename match does not prove the original absent. MD5/content equality does not identify a physical source or merge messages.')


def validate_request(params):
    if (not isinstance(params.get('logical_id'),str) or not 1<=len(params['logical_id'])<=200 or
        not isinstance(params.get('sha'),str) or not re.fullmatch('[0-9a-f]{64}',params['sha']) or
        (params.get('expected_md5') is not None and (not isinstance(params['expected_md5'],str) or not re.fullmatch('[0-9a-f]{32}',params['expected_md5']))) or
        params.get('view','current') not in ('current','restored')):raise ValueError('invalid image selection')


class ImageCache:
    """Reuse decoded pixels, never a prior binding's original-integrity proof.

    Each prepare fully streams/authenticates the current CAS, including hits and
    preview-limit paths. Serialize preparation to bound concurrent raw buffers.
    """
    def __init__(self,*,budget=128*1024**2):
        self.lock=threading.Lock();self.entries=OrderedDict();self.bytes=0;self.budget=budget;self.candidates=()
    def read(self,ident):
        if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{64}',ident):raise ValueError('invalid image artifact')
        with self.lock:
            if ident not in self.entries:raise KeyError('image preview expired; prepare again')
            binary,metadata=self.entries.pop(ident);self.entries[ident]=(binary,metadata)
            return binary
    def clear(self):
        with self.lock:self.entries.clear();self.bytes=0;self.candidates=()
    def prepare(self,archive,catalog,objects,*,logical_id,sha,expected_md5):
        listing=candidates(archive,catalog,logical_id,selected_sha=sha,expected_md5=expected_md5,limit=1);selected=listing['rows']
        if not selected:raise ValueError('original is not a retained candidate for this message checksum')
        size=selected[0]['bytes'];ident=hashlib.sha256(canonical([IMAGE_CODEC,sha]).encode()).hexdigest()
        if objects.execute('SELECT 1 FROM file WHERE hash=?',(sha,)).fetchone() is None:
            return dict(status='file_missing',raw_sha=sha,raw_preserved=False,
                sha256_original_bytes_verified=False,
                reason='selected_object_not_in_bound_cas_other_sources_not_claimed_absent')
        with self.lock:
            entry=self.entries.get(ident);reused=entry is not None
            limited=not 0<size<=MAX_IMAGE
            raw=bytearray() if entry is None and not limited else None
            for *_,block in _blocks(objects,sha,size):
                if raw is not None:raw.extend(block)
            # Exhaustion authenticates full SHA-256, chunk order, lengths,
            # decompression and chunk hashes once, before any success claim.
            if limited:return dict(status='saved_unsupported',reason='image_preview_size_limit_only',
                raw_preserved=True,sha256_original_bytes_verified=True)
            if entry is None:
                command=([sys.executable,'--media-worker'] if getattr(sys,'frozen',False) else [sys.executable,'-m','wechat_capture_next.media_decode'])
                request=dict(kind='image_bytes',data=base64.b64encode(raw).decode('ascii'),
                    candidates=[dict(aes_hex=c.key.hex(),xor_byte=c.xor_byte) for c in self.candidates])
                raw_container='v2' if raw.startswith(bytes.fromhex('070856320807')) else 'v1' if raw.startswith(bytes.fromhex('070856310807')) else 'other'
                del raw
                result=subprocess.run(command,input=json.dumps(request),text=True,capture_output=True,timeout=60,
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                if result.returncode:
                    error_type='worker_failed'
                    try:
                        value=json.loads(result.stdout[:2048]).get('error_type')
                        if isinstance(value,str) and re.fullmatch('[A-Za-z0-9_]{1,80}',value):error_type=value
                    except (ValueError,AttributeError):pass
                    return dict(status='saved_unsupported',reason='decoder_or_required_key_unavailable',raw_preserved=True,
                        sha256_original_bytes_verified=True,decoder_error_type=error_type,raw_container=raw_container)
                response=json.loads(result.stdout);metadata=response['image'];data=base64.b64decode(response['data'],validate=True)
                if (not 0<len(data)<=MAX_IMAGE or metadata['format'] not in MIMES or hashlib.sha256(data).hexdigest()!=metadata['sha256'] or
                    hashlib.md5(data).hexdigest()!=metadata['md5']):raise ValueError('decoded image worker readback differs')
                entry=(BinaryMedia(data,MIMES[metadata['format']]),metadata)
                if len(data)>self.budget:return dict(status='saved_unsupported',reason='image_memory_preview_budget_only',
                    raw_preserved=True,sha256_original_bytes_verified=True)
                while self.entries and self.bytes+len(data)>self.budget:
                    _,(expired,_)=self.entries.popitem(last=False);self.bytes-=len(expired.data)
                self.entries[ident]=entry;self.bytes+=len(data)
            else:self.entries.move_to_end(ident)
            binary,metadata=entry
            matches=[c for c in listing['hints'] if c['md5']==metadata['md5']]
            return dict(status='ready',artifact_id=ident,raw_sha=sha,raw_preserved=True,image=metadata,reused=reused,
                sha256_original_bytes_verified=True,content_checksum_matches=metadata['md5']==expected_md5 if expected_md5 is not None else None,
                content_checksum_matches_any_explicit_field=bool(matches),matching_content_checksum_fields=matches,
                association=('candidate_content_checksum_unavailable_origin_unconfirmed' if expected_md5 is None else
                    'content_checksum_equal_physical_origin_unconfirmed' if metadata['md5']==expected_md5 else 'candidate_checksum_mismatch_not_associated'),
                checksum_algorithm='md5_from_explicit_message_field_not_message_identity' if expected_md5 is not None else None,
                origin_link_confirmed=False,
                storage='bounded_RAM_only_no_plaintext_temp_files')
