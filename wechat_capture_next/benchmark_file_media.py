"""Bounded real file/video XML evidence QA, raw verification and fresh exports.

Private receipts contain technical IDs and hashes, never chat text, names,
message XML, URLs or keys. No UI, network, preview decoding or file execution.
All input SQLite/identity files remain cold guarded and all writes go to a new
owned working QA directory. No association is inferred from capture timestamps.
"""
import argparse
from collections import Counter
from contextlib import ExitStack, closing
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import time

from wechat_capture_v2.common import digest_file, stamp, write_json_new
from . import backup, file_media
from .compact_archive import CompactArchive
from .paths import local_absolute
from .state_guard import writer_lock
from .union_archive import cold_input, cold_reader

WORKING_ROOT=Path(__file__).resolve().parents[1]/'working'


def retained_prefilter(archive,catalog,budget=32*1024**2):
    """Optimization only: overflow disables it rather than omitting candidates."""
    tokens=set();names=set();video_tokens=set();used=0
    for db,table,_ in file_media._tables(archive,catalog):
        for path, in db.execute('SELECT relative_path FROM '+table):
            if not isinstance(path,str):continue
            values=[(names,PureWindowsPath(path).name.casefold())]
            video=re.fullmatch(r'([0-9a-f]{32})(?:_[a-z0-9]+)*\.(?:mp4|mkv|mov|m4v|avi|webm|3gp)',PureWindowsPath(path).name.lower())
            if video:values.append((video_tokens,video[1]))
            values.extend((tokens,m.group()) for m in re.finditer(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])',path.lower()))
            for group,value in values:
                if value in group:continue
                used+=160+4*len(value)
                if used>budget:return None
                group.add(value)
    return dict(tokens=tokens,names=names,video_tokens=video_tokens,bounded_estimated_bytes=used)


def intersects(prefilter,claims):
    return prefilter is None or any((claim['md5'] and claim['md5'] in prefilter['tokens']) or
        (claim['filename'] and claim['filename'].casefold() in prefilter['names']) or
        (claim.get('token') and claim['token'] in prefilter['video_tokens']) for claim in claims)


def sample_messages(archive,kind,limit):
    native=(43,62) if kind=='video' else (49,)
    placeholders=','.join('?' for _ in native)
    yield from (row[0] for row in archive._db.execute('''SELECT l.logical_id FROM observation_record o
        CROSS JOIN message_link m ON m.observation_id=o.observation_id
        CROSS JOIN logical_record l ON l.logical_id=m.logical_id
        WHERE (CAST(o.message_type AS INTEGER)&4294967295) IN ('''+placeholders+''')
        AND l.representative_observation_id=o.observation_id ORDER BY o.rowid DESC LIMIT ?''',(*native,limit)))


def redacted_verification(logical_id,kind,result):
    fields=('status','file_sha','bytes','md5','sha256_original_bytes_verified','content_checksum_matches',
        'association','origin_link_confirmed','preview_status','preview_reason','reason')
    value={key:result[key] for key in fields if key in result}
    value.update(logical_id=logical_id,kind=kind,
        matching_checksum_fields=sorted({claim['field'] for claim in result.get('matching_claims',[])}),
        evidence_is_not_duplicate_message_identity=True)
    return value


def run(restored,output,*,message_limit=10000,attempt_limit=16,export_target=3,max_object_bytes=64*1024**2,
        max_verified_bytes=512*1024**2,max_export_bytes=128*1024**2,kinds=('video','file'),progress=None):
    restored=local_absolute(restored);output=local_absolute(output);working=local_absolute(WORKING_ROOT)
    if not output.is_relative_to(working) or output==working or output.exists():
        raise ValueError('fresh project working QA output directory required')
    if backup._overlap(restored,output):raise ValueError('QA output overlaps restored inputs')
    if min(message_limit,attempt_limit,export_target,max_object_bytes,max_verified_bytes,max_export_bytes)<=0:
        raise ValueError('positive bounded QA limits required')
    if not kinds or any(kind not in ('video','file') for kind in kinds):raise ValueError('invalid QA kind')
    state=restored/'state';union=restored/'union'
    sources=[state/'catalog.sqlite',state/'objects.sqlite',state/'config.private.json',
        union/'archive.wua.sqlite',union/'OWNER.private.json']
    started=time.monotonic();all_counts={};selected=[];exports=[];errors=[];seen=set();verified_bytes=0;export_bytes=0
    code_paths=[Path(__file__),Path(file_media.__file__)]
    code_before={path.name:digest_file(path) for path in code_paths}
    output.mkdir(parents=False,exist_ok=False)
    write_json_new(output/'OWNER.private.json',dict(schema='next-file-video-qa-1',source_readonly=True))
    before={str(path):stamp(path) for path in sources}
    with ExitStack() as stack:
        stack.enter_context(writer_lock(state));stack.enter_context(writer_lock(union))
        for path in sources:stack.enter_context(cold_input(path))
        archive=stack.enter_context(CompactArchive(union/'archive.wua.sqlite',readonly=True,immutable=True))
        catalog=stack.enter_context(closing(cold_reader(state/'catalog.sqlite')))
        objects=stack.enter_context(closing(cold_reader(state/'objects.sqlite')))
        config=json.loads((state/'config.private.json').read_text(encoding='utf-8'))
        protected=[restored,*backup._source_roots(config)]
        if config.get('database_root'):protected.append(str(Path(config['database_root']).parent))
        prefilter=retained_prefilter(archive,catalog)
        db_before=[db.total_changes for db in (archive._db,catalog,objects)]
        logical_count=archive._db.execute('SELECT count(*) FROM logical_record').fetchone()[0]
        for kind in kinds:
            if progress:progress(kind+'_sample_started')
            counts=Counter();kind_exports=0
            for logical_id in sample_messages(archive,kind,message_limit):
                counts['messages_sampled']+=1
                claims=file_media.hints(archive,logical_id,kind=kind)
                native,native_unsupported=file_media.native_video_hints(archive,logical_id) if kind=='video' else ([],0)
                counts['native_filename_hint_messages']+=bool(native);counts['unsupported_native_observations']+=native_unsupported
                counts['unsupported_observations']+=claims['unsupported_observations']
                if not claims['claims'] and not native:
                    counts['messages_without_supported_claim']+=1;continue
                counts['messages_with_explicit_claims']+=1;counts['explicit_claims']+=len(claims['claims'])
                counts['messages_with_md5_claim']+=any(claim['md5'] for claim in claims['claims'])
                if not intersects(prefilter,[*claims['claims'],*native]):
                    counts['prefilter_no_retained_path_or_name_intersection']+=1;continue
                after='';found=False
                while True:
                    page=file_media.candidates(archive,catalog,logical_id,kind=kind,after=after,limit=50)
                    counts['candidate_pages']+=1;counts['candidate_objects_in_read_pages']+=len(page['rows'])
                    found=found or bool(page['rows'])
                    for row in sorted(page['rows'],key=lambda item:(item['bytes'],item['file_sha'])):
                        sha=row['file_sha']
                        if sha in seen:counts['duplicate_original_objects_skipped']+=1;continue
                        if counts['attempts']>=attempt_limit:break
                        if row['bytes']>max_object_bytes:
                            counts['objects_over_per_object_qa_budget']+=1;continue
                        if verified_bytes+row['bytes']>max_verified_bytes:
                            counts['objects_over_total_qa_budget']+=1;continue
                        seen.add(sha);counts['attempts']+=1
                        try:
                            result=file_media.verify(archive,catalog,objects,logical_id=logical_id,sha=sha,kind=kind)
                            detail=redacted_verification(logical_id,kind,result)
                            detail.update(candidate_evidence_rows=row['evidence_count'],
                                candidate_evidence_examples_truncated=row['evidence_examples_truncated'],
                                candidate_match_basis=sorted({basis for example in row['evidence'] for basis in example['basis']}))
                            selected.append(detail);counts['verify_status:'+result['status']]+=1
                            if result.get('sha256_original_bytes_verified'):
                                verified_bytes+=result['bytes'];counts['original_bytes_verified']+=result['bytes']
                                counts['checksum_content_matches']+=bool(result['content_checksum_matches'])
                                counts['saved_unsupported_previews']+=result.get('preview_status')=='saved_unsupported'
                                if kind_exports<export_target and export_bytes+result['bytes']<=max_export_bytes:
                                    name=kind+'-'+str(kind_exports+1)+'-'+sha[:16]+'.original'
                                    exported=file_media.export(archive,catalog,objects,logical_id=logical_id,sha=sha,
                                        kind=kind,destination=output/name,protected_roots=protected)
                                    if digest_file(output/name)!=sha:raise ValueError('independent QA export SHA readback differs')
                                    exports.append(dict(kind=kind,file_sha=sha,bytes=exported['bytes'],md5=exported['md5'],
                                        relative_output=name,association_status=exported['status'],
                                        export_readback_verified=exported['export_readback_verified'],automatically_opened=False))
                                    kind_exports+=1;export_bytes+=exported['bytes'];counts['exports_readback_verified']+=1
                        except Exception as error:
                            counts['verification_or_export_errors']+=1
                            errors.append(dict(kind=kind,logical_id=logical_id,file_sha=sha,error_type=type(error).__name__))
                    if counts['attempts']>=attempt_limit or page['next_after'] is None:break
                    after=page['next_after']
                counts['candidate_messages']+=found
                if not found:counts['association_unknown_after_candidate_lookup']+=1
                if counts['attempts']>=attempt_limit:
                    counts['stopped_at_explicit_qa_attempt_bound']=1;break
            all_counts[kind]=dict(counts)
            if progress:progress(kind+'_sample_finished')
        if logical_count!=archive._db.execute('SELECT count(*) FROM logical_record').fetchone()[0]:
            raise ValueError('QA changed logical message count')
        if db_before!=[db.total_changes for db in (archive._db,catalog,objects)]:
            raise ValueError('QA wrote input SQLite rows')
    unchanged=all(stamp(path)==before[str(path)] for path in sources)
    if not unchanged:raise ValueError('QA input file metadata changed')
    result=dict(schema='next-file-video-evidence-qa-1',scope='bounded_real_restored_B_XML_candidate_original_byte_and_export_QA',
        elapsed_seconds=time.monotonic()-started,counts=all_counts,selected_private=selected,exports_private=exports,errors_private=errors,
        total_unique_original_bytes_verified=verified_bytes,total_export_bytes=export_bytes,
        input_files_unchanged_by_cold_guard_and_stamp=unchanged,input_SQLite_total_changes_zero=True,
        input_logical_message_count_unchanged=True,writer_locks_cold_guards_and_connections_released=True,
        prefilter_disabled_for_budget=prefilter is None,prefilter_estimated_bytes=None if prefilter is None else prefilter['bounded_estimated_bytes'],
        limits=dict(message_limit_per_kind=message_limit,attempt_limit_per_kind=attempt_limit,export_target_per_kind=export_target,
            max_object_bytes=max_object_bytes,max_verified_bytes=max_verified_bytes,max_export_bytes=max_export_bytes),
        source_hashes_before=code_before,source_hashes_after={path.name:digest_file(path) for path in code_paths},
        no_UI_network_execution_or_decoder=True,
        limitation='Names alone remain candidates; MD5 equality is content evidence, not native physical provenance or duplicate-message identity. Missing path matches do not prove absence. No browser playability claim.')
    result['code_changed_during_run']=result['source_hashes_before']!=result['source_hashes_after']
    write_json_new(output/'evidence.private.json',result)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restored',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--message-limit',type=int,default=10000);parser.add_argument('--attempt-limit',type=int,default=16)
    parser.add_argument('--export-target',type=int,default=3)
    parser.add_argument('--kind',choices=('video','file','all'),default='all');args=parser.parse_args(argv)
    value=run(args.restored,args.output,message_limit=args.message_limit,attempt_limit=args.attempt_limit,
        export_target=args.export_target,kinds=('video','file') if args.kind=='all' else (args.kind,),
        progress=lambda phase:print(json.dumps(dict(phase=phase)),flush=True))
    print(json.dumps({key:value[key] for key in ('counts','elapsed_seconds','total_unique_original_bytes_verified',
        'total_export_bytes','writer_locks_cold_guards_and_connections_released','code_changed_during_run')}),flush=True)


if __name__=='__main__':main()
