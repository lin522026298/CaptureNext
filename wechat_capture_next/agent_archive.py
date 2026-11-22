"""Scoped, headless reads of a CaptureNext installation's published archive."""
import argparse
from contextlib import ExitStack, closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

from wechat_capture_next import file_media, image_media, viewer, viewer_media
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.console import _file
from wechat_capture_next.paths import local_absolute, safe_name
from wechat_capture_next.recovery_core import _binding_value
from wechat_capture_next.union_archive import cold_input
from wechat_capture_next.union_assets import _blocks


class Refusal(ValueError):
    """Only program-owned, non-private reason strings may reach stdout."""


@contextmanager
def read_mode(stack, path):
    _file(path)
    with ExitStack() as trial:
        try:
            trial.enter_context(cold_input(path))
        except (OSError, ValueError):
            # Never open a hot WAL as immutable, nor create missing SHM/WAL
            # deliberately. Use a normal read transaction on a published WAL.
            for suffix in ('-wal', '-shm'):
                if not Path(str(path)+suffix).is_file():
                    raise Refusal('archive_busy_or_unsettled_retry_without_starting_writer') from None
                _file(Path(str(path)+suffix))
            journal = Path(str(path)+'-journal')
            if journal.exists():
                raise Refusal('archive_busy_or_unsettled_retry_without_starting_writer') from None
            yield False
        else:
            stack.enter_context(trial.pop_all())
            yield True


def state_db(stack, path):
    with read_mode(stack, path) as immutable:
        db = stack.enter_context(closing(sqlite3.connect(path.as_uri()+'?mode=ro'+
            ('&immutable=1' if immutable else ''), uri=True, timeout=2)))
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute('BEGIN')
    return db


def roots(root):
    base = local_absolute(root)/'archives'/'wechat-next'
    binding = _binding_value(base)
    if binding:
        receipt = local_absolute(binding['receipt_root'])
        marker = receipt/'DELIVERY.complete.private.json'
        _file(marker)
        if json.loads(marker.read_text('utf-8')).get('snapshot_id') != binding['snapshot_id']:
            raise Refusal('active_restore_receipt_mismatch')
        return base, receipt/'state', receipt/'union', binding
    return base, base/'state', base/'unified', None


def account_rows(db):
    # Stored columns only. Do not expand all bodies or return any chat text.
    return [dict(r) for r in db.execute('''SELECT account_alias AS account,
        min(event_time) AS first_observed_time,max(event_time) AS last_observed_time,
        count(*) AS observation_count FROM observation_record
        WHERE account_alias IS NOT NULL AND account_alias<>'' GROUP BY account_alias
        ORDER BY account_alias''')]


def scoped(archive, account, ident):
    row = archive._db.execute('''SELECT o.account_alias FROM logical_record l
        JOIN observation_record o ON o.observation_id=l.representative_observation_id
        WHERE l.logical_id=? AND o.account_alias=?''',(ident,account)).fetchone()
    if row is None:
        raise Refusal('message_not_found_in_selected_account')
    if archive._db.execute('''SELECT 1 FROM message_link l JOIN observation_record o
        ON o.observation_id=l.observation_id WHERE l.logical_id=? AND o.account_alias IS NOT ? LIMIT 1''',
        (ident,account)).fetchone():
        raise Refusal('message_has_cross_account_or_unscoped_observations')


def conversations(archive, args):
    query = args.query or ''
    like = '%'+query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
    sql = 'WHERE o.account_alias=?'
    params = [args.account]
    if query:
        sql += " AND (o.conversation_id LIKE ? ESCAPE '\\'"
        params.append(like)
        if viewer._present(archive,'next_viewer_identity'):
            sql += " OR EXISTS(SELECT 1 FROM next_viewer_identity i WHERE i.account_alias=o.account_alias AND i.username=o.conversation_id AND i.name LIKE ? ESCAPE '\\')"
            params.append(like)
        sql += ')'
    rows = [dict(r) for r in archive._db.execute('''SELECT o.account_alias,o.conversation_id,
        count(*) AS message_count,max(o.event_time) AS last_time '''+viewer._representatives(archive)+sql+'''
        GROUP BY o.account_alias,o.conversation_id ORDER BY last_time DESC,o.conversation_id
        LIMIT ? OFFSET ?''',(*params,args.limit+1,args.offset))]
    return dict(rows=viewer.decorate(archive,rows[:args.limit]),next_offset=args.offset+args.limit if len(rows)>args.limit else None)


def file_target(base, state, union, target):
    target = local_absolute(target)
    safe_name(target.name)
    protected = [base,state,union]
    # Read source *locations* for output protection only; never open a keyring
    # or any native client database. The CLI never creates output directories.
    conf = state/'config.private.json'
    _file(conf)
    config = json.loads(conf.read_text('utf-8'))
    if config.get('database_root'):
        protected.append(local_absolute(config['database_root'],lexical=True).parent)
    if config.get('asset_root'):
        protected.append(local_absolute(config['asset_root'],lexical=True))
    if any(target.is_relative_to(p) for p in protected) or not target.parent.is_dir():
        raise Refusal('output_must_be_new_in_existing_directory_outside_source_and_archive')
    if os.path.lexists(target):
        raise Refusal('output_already_exists')
    return target,protected


def output_bytes(target, parts, expected_sha):
    created = None
    try:
        digest = hashlib.sha256(); size = 0
        with target.open('xb') as out:
            created = os.fstat(out.fileno())
            for data in parts:
                digest.update(data); size += len(data); out.write(data)
        with target.open('rb') as f:
            readback = hashlib.file_digest(f,'sha256').hexdigest()
        if digest.hexdigest()!=expected_sha or readback!=expected_sha:
            raise Refusal('attachment_hash_mismatch')
        return dict(path=str(target),bytes=size,sha256=readback,verified=True)
    except BaseException:
        if created is not None and target.exists() and os.path.samestat(created,target.lstat()):
            target.unlink()
        raise


def scoped_attachment_page(page, *, image=False):
    """Candidates use the archive-wide object pool, not account-bound paths."""
    checksum_claims = [hint for hint in page['hints']
                       if hint.get('md5') and hint.get('role') != 'thumbnail']
    if not checksum_claims:
        page['rows'] = []
        page['next_after'] = None
        if page['status'] == 'candidate':
            page['status'] = 'association_unknown'
    for row in page['rows']:
        for item in row['evidence']:
            for key in ('source_id', 'relative_path', 'example_path'):
                item.pop(key,None)
        if image:
            row['md5s'] = sorted(set(row['md5s']) & {hint['md5'] for hint in checksum_claims})
    page['candidate_pool'] = 'shared_retained_objects_not_account_provenance'
    page['account_scope'] = 'message_claims_only_no_candidate_source_paths'
    return page


def execute(args):
    base,state,union,binding = roots(args.root)
    path = union/'archive.wua.sqlite'
    with ExitStack() as stack:
        with read_mode(stack,path) as immutable:
            archive = stack.enter_context(CompactArchive(path,readonly=True,immutable=immutable))
        archive._db.execute('BEGIN')
        if binding:
            archived = archive._db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
            if archived is None or archived[0]!=binding['union_id']:
                raise Refusal('active_union_identity_mismatch')
        if args.operation=='accounts':
            return dict(rows=account_rows(archive._db),scope='published_local_archive_not_login_state')
        if args.operation=='conversations':
            return conversations(archive,args)
        if args.operation in ('search','messages'):
            result = viewer.messages(archive,account_alias=args.account,conversation_id=args.conversation,
                sender_id=args.sender,message_type=args.message_type,since=args.since,until=args.until,
                search=args.query,limit=args.limit,offset=args.offset)
            for row in result['rows']:
                scoped(archive,args.account,row['logical_id'])
            return result
        scoped(archive,args.account,args.id)
        if args.operation=='context':
            result = viewer.context(archive,args.id,before=args.limit//2,limit=args.limit)
            for row in result['rows']:
                scoped(archive,args.account,row['logical_id'])
            return result
        if args.operation=='detail':
            result = viewer.detail(archive,args.id,candidate_offset=args.offset)
            # Candidate pairing can mention another account; do not return it
            # through scoped account reads. Raw versions are opt-in via detail.
            for key in ('candidates','candidate_next_offset'):
                result.pop(key,None)
            return result
        catalog = state_db(stack,state/'catalog.sqlite')
        if binding:
            found = catalog.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()
            if found is None or found[0]!=binding['catalog_instance']:
                raise Refusal('active_catalog_identity_mismatch')
        voice = lambda:viewer_media.for_message(archive,args.id)
        if args.operation=='attachments':
            return dict(file_video=scoped_attachment_page(file_media.candidates(
                    archive,catalog,args.id,after=args.after_file,limit=args.limit)),
                image=scoped_attachment_page(image_media.candidates(
                    archive,catalog,args.id,after=args.after_image,limit=args.limit),image=True),voice=voice())
        if args.operation!='export':
            raise Refusal('unsupported_operation')
        target,protected = file_target(base,state,union,args.out)
        objects = state_db(stack,state/'objects.sqlite')
        opts = dict(logical_id=args.id,sha=args.sha)
        if args.kind in ('file','video'):
            try:
                return file_media.export(archive,catalog,objects,kind=args.kind,destination=target,
                    protected_roots=protected,require_linked=True,**opts)
            except (file_media.UnverifiedOriginal, FileNotFoundError) as error:
                raise Refusal('original_missing_or_not_confirmed_for_this_message') from error
        if args.kind=='voice':
            matches = [r for r in voice()['rows'] if r['status']=='linked' and r['file_sha']==args.sha]
            if not matches:
                raise Refusal('voice_original_missing_or_not_confirmed_for_this_message')
            size = objects.execute('SELECT bytes FROM file WHERE hash=?',(args.sha,)).fetchone()
            if size is None:
                raise Refusal('voice_original_missing')
            return dict(kind='voice',representation='archived_native_bytes',**output_bytes(target,
                (r[-1] for r in _blocks(objects,args.sha,size[0])),args.sha))
        if not args.expected_md5:
            raise Refusal('image_requires_explicit_message_content_checksum')
        claims, _ = image_media.hints(archive,args.id)
        if args.expected_md5 not in {h['md5'] for h in claims if h['role']!='thumbnail'}:
            raise Refusal('image_requires_explicit_message_content_checksum')
        cache = image_media.ImageCache()
        ready = cache.prepare(archive,catalog,objects,expected_md5=args.expected_md5,**opts)
        if ready['status']!='ready' or not ready['content_checksum_matches']:
            raise Refusal('image_not_decodable_or_content_checksum_does_not_match')
        image = cache.read(ready['artifact_id'])
        return dict(kind='image',representation='verified_decoded_image',mime=image.content_type,
            raw_sha256=args.sha,**output_bytes(target,[image.data],ready['image']['sha256']))


def parse(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True,type=Path,help='CaptureNext installation root, not the WeChat client directory')
    sub = parser.add_subparsers(dest='operation',required=True)
    for op in ('accounts','conversations','search','messages','context','detail','attachments','export'):
        p = sub.add_parser(op)
        if op!='accounts':p.add_argument('--account',required=True)
        if op in ('context','detail','attachments','export'):p.add_argument('--id',required=True)
        if op in ('conversations','search','messages','context','detail','attachments'):
            p.add_argument('--limit',type=int,default=20);p.add_argument('--offset',type=int,default=0)
        if op in ('conversations','search','messages'):p.add_argument('--query',required=op=='search')
        if op in ('search','messages'):
            for flag in ('conversation','sender','message-type','since','until'):p.add_argument('--'+flag)
        if op=='attachments':
            p.add_argument('--after-file',default='');p.add_argument('--after-image',default='')
        if op=='export':
            p.add_argument('--kind',choices=('file','video','voice','image'),required=True)
            p.add_argument('--sha',required=True);p.add_argument('--expected-md5')
            p.add_argument('--out',type=Path,required=True)
    return parser.parse_args(argv)


def main(argv=None):
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    args = parse(argv)
    try:
        if hasattr(args,'limit') and not (1<=args.limit<=100 and 0<=args.offset<=100000):
            raise Refusal('invalid_page')
        if getattr(args,'account',None) is not None and (not args.account.strip() or len(args.account)>200):
            raise Refusal('explicit_account_required')
        for field,bound in (('query',1000),('id',200)):
            value = getattr(args,field,None)
            if value is not None and (not value.strip() or len(value)>bound):
                raise Refusal('invalid_'+field)
        if args.operation=='export' and (not re.fullmatch('[0-9a-f]{64}',args.sha) or
                (args.expected_md5 and not re.fullmatch('[0-9a-f]{32}',args.expected_md5))):
            raise Refusal('invalid_attachment_hash')
        result = dict(platform='wechat',operation=args.operation,account=getattr(args,'account',None),
            result=execute(args))
        code = 0
    except (OSError,ValueError,TypeError,KeyError,RuntimeError,sqlite3.Error) as error:
        result = dict(error_type=type(error).__name__,reason=str(error) if isinstance(error,Refusal) else 'read_or_export_unavailable')
        code = 2
    print(json.dumps(result,ensure_ascii=False))
    return code


if __name__=='__main__':
    raise SystemExit(main())
