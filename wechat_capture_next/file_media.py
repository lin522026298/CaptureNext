"""Read-only file/video evidence projection and explicit streaming raw export.

No timestamp matching, network retrieval, external execution, persistent links,
or message deduplication. A content checksum match is NOT physical provenance.
Only literal, whitelisted XML fields are understood; everything else stays raw.
"""
import base64
import hashlib
import heapq
import itertools
import json
import os
from pathlib import PureWindowsPath
import re

from defusedxml import ElementTree as XML

from .paths import local_absolute
from .union_assets import _blocks

MAX_XML = 4 * 1024**2
_MD5 = re.compile(r'[0-9a-fA-F]{32}')
_SHA = re.compile(r'[0-9a-f]{64}')


def validate_request(params):
    if (not isinstance(params.get('logical_id'), str) or not 1 <= len(params['logical_id']) <= 200
            or not isinstance(params.get('sha'), str) or not _SHA.fullmatch(params['sha'])
            or params.get('kind') not in (None, 'file', 'video')
            or params.get('view', 'current') not in ('current', 'restored')):
        raise ValueError('invalid file/video selection')


def _checksum(value):
    return value.lower() if isinstance(value, str) and _MD5.fullmatch(value) and value != '0'*32 else None


def _length(value):
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,19}', value):
        number = int(value)
        return number if number < 2**63 else None
    return None


def _filename(value):
    # A filename claim is metadata only, never an output path or launch target.
    if (not isinstance(value, str) or not value or len(value) > 1024
            or value in ('.', '..') or any(c in value for c in ('/', '\\', '\x00'))
            or any(ord(c) < 32 for c in value)):
        return None
    return value


def hints(archive, logical_id, *, kind=None):
    """Return independent claims per observation; do not combine revisions."""
    if kind not in (None, 'file', 'video'):
        raise ValueError('unsupported attachment kind')
    claims = []; unsupported = 0; eligible = 0
    for row in archive._db.execute('''SELECT o.observation_id,o.message_type,o.body_text
            FROM message_link l JOIN observation_record o ON o.observation_id=l.observation_id
            WHERE l.logical_id=? ORDER BY o.observation_id''', (logical_id,)):
        try:
            native_type = int(row['message_type']) & 4294967295
        except (ValueError, TypeError):
            continue
        if native_type not in (43, 49, 62) or row['body_text'] is None:
            continue
        eligible += 1
        body = archive.pool.get_text(row['body_text']); start = body.find('<msg')
        if start < 0 or len(body) > MAX_XML:
            unsupported += 1; continue
        try:
            root = XML.fromstring(body[start:])
        except Exception:
            unsupported += 1; continue
        if root.tag != 'msg':
            unsupported += 1; continue
        found = False
        if native_type in (43, 62) and kind in (None, 'video'):
            for element in root.findall('videomsg'):
                for field in ('md5', 'originsourcemd5', 'rawmd5'):
                    md5 = _checksum(element.get(field))
                    if md5:
                        claims.append(dict(observation_id=row['observation_id'], kind='video',
                            field='videomsg.'+field, md5=md5,
                            bytes=_length(element.get('length' if field == 'md5' else 'rawlength')) if field in ('md5', 'rawmd5') else None,
                            filename=_filename(element.get('filename')),
                            role='original' if field in ('originsourcemd5', 'rawmd5') else 'video'))
                        found = True
        if native_type == 49 and kind in (None, 'file'):
            for app in root.findall('appmsg'):
                if app.findtext('type') != '6':
                    continue
                for element in app.findall('appattach'):
                    filename = _filename(element.findtext('filename')) or _filename(app.findtext('title'))
                    size = _length(element.findtext('totallen'))
                    checksums = []
                    for field in ('filemd5', 'md5'):
                        for value in (element.get(field), *(v.text for v in element.findall(field))):
                            md5 = _checksum(value)
                            if md5 and (field, md5) not in checksums:
                                checksums.append((field, md5))
                    # Filename+size is a candidate, never confirmed without MD5.
                    for field, md5 in checksums or [('filename_and_size', None)]:
                        if md5 is None and (filename is None or size is None):
                            continue
                        claims.append(dict(observation_id=row['observation_id'], kind='file',
                            field='appmsg.appattach.'+field, md5=md5, bytes=size,
                            filename=filename, role='file'))
                        found = True
        if not found:
            unsupported += 1
    return dict(claims=claims, unsupported_observations=unsupported, eligible_observations=eligible)


def _tables(archive, catalog):
    for db, table, scope in ((archive._db, 'next_union_asset_observation', 'retained_union'),
            (catalog, 'asset_history', 'current_state_history')):
        if db is not None and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            yield db, table, scope


def _wire_fields(data):
    """Strict bounded wire framing, no inferred image/video field meanings."""
    if len(data)>1024**2:raise ValueError('oversized native packed field')
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


def native_video_hints(archive,logical_id):
    """Observed video packed_info_data 4 -> 8 literal filename identifier.

    Independently observed in 2,313 type43 archive observations, 268 intersections
    with actual video basenames. Not inherited from image field 3 -> 4, and NOT a
    content MD5 claim. Unknown future/duplicate/truncated shapes remain unknown.
    """
    result=[];unsupported=0
    for row in archive._db.execute('''SELECT o.observation_id,o.raw_record_json FROM message_link l
            JOIN observation_record o ON o.observation_id=l.observation_id WHERE l.logical_id=?
            AND (CAST(o.message_type AS INTEGER)&4294967295)=43''',(logical_id,)):
        try:
            text=archive.pool.get_text(row['raw_record_json'])
            if len(text)>4*1024**2:raise ValueError('oversized native raw record')
            item=json.loads(text).get('packed_info_data')
            if item is None:continue
            if not isinstance(item,dict) or set(item)!={'$wua_binary'}:raise ValueError('unsupported native binary representation')
            value=item['$wua_binary']
            if (value.get('encoding')!='base64' or type(value.get('byte_length')) is not int or
                not 0<=value['byte_length']<=1024**2 or not isinstance(value.get('data'),str) or
                len(value['data'])>1024**2*4//3+16):raise ValueError('native binary bounds')
            data=base64.b64decode(value['data'],validate=True)
            if len(data)!=value['byte_length'] or hashlib.sha256(data).hexdigest()!=value.get('sha256'):
                raise ValueError('native binary SHA/length differs')
            fields=_wire_fields(data)
            if any(n==4 and wire!=2 for n,wire,_ in fields):raise ValueError('unexpected native video parent wire')
            parent=[value for n,wire,value in fields if n==4 and wire==2]
            if not parent:continue
            fields=_wire_fields(parent[0])
            if any(n==8 and wire!=2 for n,wire,_ in fields):raise ValueError('unexpected native video identifier wire')
            identifiers=[value for n,wire,value in fields if n==8 and wire==2]
            if not identifiers:continue
            token=identifiers[0].decode('ascii').lower()
            if not _MD5.fullmatch(token) or token=='0'*32:raise ValueError('invalid native video filename identifier')
            result.append(dict(observation_id=row['observation_id'],kind='video',
                field='raw_record.packed_info_data.protobuf.4.8',token=token,
                md5=None,bytes=None,filename=None,packed_sha256=value['sha256'],
                identifier_kind='native_video_filename_identifier_candidate',content_md5_claim=False,
                semantics='observed_video_basename_token_not_confirmed_native_schema'))
        except (ValueError,TypeError,KeyError,AttributeError,UnicodeError):unsupported+=1
    return result,unsupported


def _path_basis(path, claim):
    if not isinstance(path, str):
        return []
    result = []
    if claim.get('identifier_kind')=='native_video_filename_identifier_candidate':
        name=PureWindowsPath(path).name.lower()
        if re.fullmatch(re.escape(claim['token'])+r'(?:_[a-z0-9]+)*\.(?:mp4|mkv|mov|m4v|avi|webm|3gp)',name):
            result.append('native_video_basename_identifier_not_content_md5')
        return result
    # Exact token, not an arbitrary substring embedded in a longer hex string.
    if claim['md5'] and re.search(r'(?<![0-9a-f])'+claim['md5']+r'(?![0-9a-f])', path.lower()):
        result.append('explicit_checksum_token_in_retained_path')
    if claim['filename'] and PureWindowsPath(path).name.casefold() == claim['filename'].casefold():
        result.append('explicit_filename_equal')
    return result


def candidates(archive, catalog, logical_id, *, kind=None, after='', selected_sha=None, limit=50):
    """Metadata-only candidates, all history paginated, no original-byte scan."""
    if after and not _SHA.fullmatch(after):
        raise ValueError('invalid attachment cursor')
    if selected_sha is not None and (not isinstance(selected_sha, str) or not _SHA.fullmatch(selected_sha)):
        raise ValueError('invalid attachment hash')
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError('invalid attachment page size')
    result = hints(archive, logical_id, kind=kind); streams = []
    native,native_unsupported=native_video_hints(archive,logical_id) if kind in (None,'video') else ([],0)
    if not result['claims'] and not native:
        return dict(status='unsupported', rows=[], hints=[], next_after=None,
            unsupported_observations=result['unsupported_observations'],
            native_filename_hints=[],unsupported_native_observations=native_unsupported,
            scope='no_supported_explicit_file_or_video_claim',
            limitation='No supported XML claim; this does not prove the original absent.')
    for db, table, scope in _tables(archive, catalog):
        args = [after]; where = 'file_sha>?'
        if selected_sha is not None:
            where += ' AND file_sha=?'; args.append(selected_sha)
        cursor = db.execute('SELECT file_sha,bytes,source_id,relative_path FROM '+table+' WHERE '+where+' ORDER BY file_sha', args)

        def stream(cursor=cursor, scope=scope):
            for sha, size, source, path in cursor:
                if not isinstance(sha, str) or not _SHA.fullmatch(sha) or type(size) is not int or size < 0:
                    raise ValueError('invalid retained attachment metadata')
                evidence = []
                for claim in [*result['claims'],*native]:
                    basis = _path_basis(path, claim)
                    if basis:
                        evidence.append(dict(scope=scope, source_id=source, relative_path=path,
                            claim=claim, basis=basis, length_matches=claim['bytes'] is None or claim['bytes'] == size))
                if evidence:
                    yield sha, size, evidence
        streams.append(stream())
    rows = []; more = False
    for sha, group in itertools.groupby(heapq.merge(*streams, key=lambda value:value[0]), key=lambda value:value[0]):
        size = None; evidence_count = 0; evidence = []
        for _, length, values in group:
            if size is not None and size != length:
                raise ValueError('retained attachment lengths conflict')
            size = length; evidence_count += len(values)
            # Metadata may have millions of repeated history rows. Keep a bounded
            # example list and exact count; content variants are never discarded.
            evidence.extend(values[:max(0, 64-len(evidence))])
        if len(rows) == limit:
            more = True; break
        rows.append(dict(file_sha=sha, bytes=size, status='candidate', evidence=evidence,
            evidence_count=evidence_count, evidence_examples_truncated=evidence_count > len(evidence),
            origin_link_confirmed=False, evidence_is_not_duplicate_message_identity=True))
    status = 'candidate' if rows else 'association_unknown'
    return dict(status=status, rows=rows, hints=result['claims'], unsupported_observations=result['unsupported_observations'],
        native_filename_hints=native,unsupported_native_observations=native_unsupported,
        next_after=rows[-1]['file_sha'] if more else None,
        scope='all_retained_metadata_history_not_all_possible_originals',
        missing_scope='no_matching_retained_metadata_candidate_not_proof_original_absent',
        limitation='No time matching. Names and MD5 do not prove physical origin or identify duplicate messages.')


def _selected(archive, catalog, logical_id, sha, kind):
    validate_request(dict(logical_id=logical_id, sha=sha, kind=kind))
    rows = candidates(archive, catalog, logical_id, kind=kind, selected_sha=sha, limit=1)['rows']
    if not rows:
        raise ValueError('object is not a retained candidate for this message')
    return rows[0]


def _consume(objects, row, sink=None):
    digest = hashlib.md5(); length = 0
    for *_, block in _blocks(objects, row['file_sha'], row['bytes']):
        digest.update(block); length += len(block)
        if sink is not None:
            sink.write(block)
    return digest.hexdigest(), length


def _result(row, claims, md5, length):
    equal = [c for c in claims if c['md5'] == md5 and (c['bytes'] is None or c['bytes'] == length)]
    return dict(status='linked' if equal else 'candidate', file_sha=row['file_sha'], bytes=length, md5=md5,
        raw_preserved=True, sha256_original_bytes_verified=True, content_checksum_matches=bool(equal),
        matching_claims=equal, association='explicit_md5_content_equal_physical_origin_unconfirmed' if equal else 'unconfirmed_candidate',
        origin_link_confirmed=False, evidence_is_not_duplicate_message_identity=True,
        selection_basis=sorted({basis for item in row.get('evidence',[]) for basis in item['basis']}),
        native_filename_identifier_is_not_content_md5=True,
        preview_status='saved_unsupported', preview_reason='no_external_file_execution_or_video_playability_claim',
        checksum_limitation='MD5 is legacy content evidence, not collision-resistant authenticity or native origin evidence.')


def verify(archive, catalog, objects, *, logical_id, sha, kind=None):
    row = _selected(archive, catalog, logical_id, sha, kind)
    if objects.execute('SELECT 1 FROM file WHERE hash=?', (sha,)).fetchone() is None:
        return dict(status='file_missing', file_sha=sha, bytes=row['bytes'],
            reason='selected_object_not_in_bound_cas_other_sources_not_claimed_absent',
            sha256_original_bytes_verified=False, content_checksum_matches=False,
            origin_link_confirmed=False, evidence_is_not_duplicate_message_identity=True)
    md5, length = _consume(objects, row)
    return _result(row, hints(archive, logical_id, kind=kind)['claims'], md5, length)


def export(archive, catalog, objects, *, logical_id, sha, destination, protected_roots, kind=None):
    """Write once to an explicitly supplied fresh local path; never auto-open.

    Caller MUST include the bound account/source roots in protected_roots. This
    independent layer additionally protects archive and CAS/catalog directories.
    It creates no output directories and no temporary duplicate of the original.
    """
    if not protected_roots:
        raise ValueError('explicit protected source roots required')
    target = local_absolute(destination)
    roots = [local_absolute(value) for value in protected_roots]
    for db in (archive._db, catalog, objects):
        if db is None:
            continue
        for _, name, path in db.execute('PRAGMA database_list'):
            if name == 'main' and path:
                roots.append(local_absolute(path).parent)
    if any(target == root or target.is_relative_to(root) for root in roots):
        raise ValueError('export overlaps protected archive, CAS, or source root')
    if not target.parent.is_dir():
        raise ValueError('explicit existing output directory required')
    row = _selected(archive, catalog, logical_id, sha, kind)
    if objects.execute('SELECT 1 FROM file WHERE hash=?', (sha,)).fetchone() is None:
        raise FileNotFoundError('selected original is not in the bound CAS')
    created = None
    try:
        with target.open('xb') as stream:
            created = os.fstat(stream.fileno())
            md5, length = _consume(objects, row, stream)
            stream.flush(); os.fsync(stream.fileno())
        # Independent readback of the requested deliverable, in bounded blocks.
        actual_sha = hashlib.sha256(); actual_md5 = hashlib.md5(); actual_length = 0
        with target.open('rb') as stream:
            for block in iter(lambda: stream.read(1024**2), b''):
                actual_sha.update(block); actual_md5.update(block); actual_length += len(block)
        if (actual_sha.hexdigest() != sha or actual_md5.hexdigest() != md5 or actual_length != length):
            raise ValueError('export readback differs from authenticated original')
        result = _result(row, hints(archive, logical_id, kind=kind)['claims'], md5, length)
        result.update(destination=str(target), exported=True, export_readback_verified=True, automatically_opened=False)
        return result
    except BaseException:
        # Only our freshly created failed output is removed, never incumbents.
        if created is not None:
            try:
                current = target.lstat()
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    target.unlink()
            except FileNotFoundError:
                pass
        raise
