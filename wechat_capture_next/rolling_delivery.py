"""New atomic paired repository; legacy repositories stay separate/readable."""
from contextlib import ExitStack
import json
from pathlib import Path

from wechat_capture_v2.common import digest_file, write_json_new
from . import backup as legacy, pair_repository as repository, union_delivery as delivery
from .compact_archive import CompactArchive
from .state_guard import writer_lock
from .union_archive import cold_input
from .union_assets import verify_union_assets
from .union_backup import ensure_union_id


def backup(state,union,repo,*,provenance=None,include_secrets=False,block_bytes=repository.DEFAULT_BLOCK,
           object_block_bytes=repository.DEFAULT_OBJECT_BLOCK,fault=None,_memo=None):
    repository.require(type(include_secrets) is bool,'include_secrets must be boolean')
    repository._leaf_size('state/objects.sqlite',block_bytes,object_block_bytes)
    state=legacy._parents(state);union=legacy._parents(union)
    # Output/source boundary refusal precedes the writer-lock file creation.
    config=delivery._config(state)
    repo=legacy._guard_location(repo,state,legacy._source_roots(config))
    delivery._disjoint([state,union,repo])
    with writer_lock(state):
        return backup_owned(state,union,repo,provenance=provenance,include_secrets=include_secrets,
                            block_bytes=block_bytes,object_block_bytes=object_block_bytes,fault=fault,_memo=_memo)


def backup_owned(state,union,repo,*,provenance=None,include_secrets=False,
                 block_bytes=repository.DEFAULT_BLOCK,object_block_bytes=repository.DEFAULT_OBJECT_BLOCK,fault=None,_memo=None):
    def phase(name):
        if fault:fault(name,None)
    phase('pair_preflight')
    repository.require(type(include_secrets) is bool,'include_secrets must be boolean')
    repository._leaf_size('state/objects.sqlite',block_bytes,object_block_bytes)
    state=legacy._parents(state);union=legacy._parents(union);config=delivery._config(state)
    repo=legacy._guard_location(repo,state,legacy._source_roots(config))
    delivery._disjoint([state,union,repo])
    with writer_lock(union):
        path,formal_owner=delivery._formal(union)
        delivery._state_owner(state,formal_owner)
        union_id=ensure_union_id(path)
        owner=dict(schema=repository.SCHEMA,catalog_instance=formal_owner['catalog_instance'],union_id=union_id)
        if repo.exists():repository.location(repo,owner)
        # Build only the complete inventory first; no duplicate table/FK/asset
        # decompression when an independently authenticated exact cut exists.
        with delivery._offline(state,readonly=False,configuration=True) as service:
            legacy._consistent_config(service)
            candidate={'state/'+n:p for n,p in legacy._files(service,include_secrets,verify_pages=False)}
        candidate.update({'union/archive.wua.sqlite':path,'union/OWNER.private.json':union/'OWNER.private.json'})
        if provenance is not None:
            provenance=legacy._parents(provenance)
            delivery._disjoint([state,union,repo,provenance])
            for name in ('pre-evidence-catalog.sqlite.zst','legacy-bag-derived.tar.zst'):
                source=provenance/name;legacy._file(source);candidate['provenance/'+name]=source
        protected={str(state),str(union),*legacy._source_roots(config),str(repo)}
        if provenance is not None:protected.add(str(provenance))
        if config.get('database_root'):protected.add(str(Path(config['database_root']).parent))
        scope=dict(verification_profile='identities-native-media-20261022-1',origin_state=str(state),origin_union=str(union),source_roots=legacy._source_roots(config),
            protected_roots=sorted(protected),includes_secrets=include_secrets,
            provenance_included=provenance is not None)
        with ExitStack() as stack:
            for source in candidate.values():stack.enter_context(cold_input(source))
            phase('exact_cut_probe')
            same=repository.unchanged(repo,owner,candidate,scope,block_bytes=block_bytes,object_block_bytes=object_block_bytes,_memo=_memo)
        if same is not None:
            # This point was authenticated under unchanged's cold guards.
            # Pending is a read-only hint, never permission to mutate outside
            # that guarded proof or force a second full govern/readback here.
            pending=repository.maintenance_pending(repo)
            same['governance']=dict(pending,maintenance_deferred=bool(pending['cleanup_pending']),
                                    cleanup_performed=False)
            return dict(same,format=repository.SCHEMA,repository=str(repo),attachments_closed=True,
                capture_started=False,login_started=False,legacy_repositories_touched=False)
        with delivery._offline(state,readonly=False,configuration=True) as service:
            legacy._consistent_config(service)
            phase('state_deep_verification')
            with legacy._frozen(service,object_proof=True) as object_proof:
                with CompactArchive(path) as archive:
                    phase('union_deep_verification')
                    integrity=archive.integrity_check()
                    if integrity.get('quick_check')!=['ok'] or integrity.get('foreign_key_check') or not integrity.get('fts_verified'):
                        raise ValueError('union integrity failed before paired backup')
                    phase('union_attachment_verification')
                    assets=verify_union_assets(archive,service,deep=True,object_proof=object_proof)
                    from .viewer_media import verify as verify_media
                    media=verify_media(archive,service,deep=True,object_proof=object_proof)
                    if assets.get('closure_complete') is not True:raise ValueError('whole attachment closure required')
                files={'state/'+name:path for name,path in legacy._files(service,include_secrets)}
        # All owned writers are closed before the OS guarded file-tree cut.
        files.update({'union/archive.wua.sqlite':path,'union/OWNER.private.json':union/'OWNER.private.json'})
        if provenance is not None:
            provenance=legacy._parents(provenance)
            delivery._disjoint([state,union,repo,provenance])
            for name in ('pre-evidence-catalog.sqlite.zst','legacy-bag-derived.tar.zst'):
                source=provenance/name;legacy._file(source);files['provenance/'+name]=source
        context=dict(scope,asset_binding=assets,media_binding=media,integrity=integrity)
        with ExitStack() as stack:
            for source in files.values():stack.enter_context(cold_input(source))
            phase('repository_tree_publish')
            result=repository.publish(repo,owner,files,context,block_bytes=block_bytes,object_block_bytes=object_block_bytes,fault=fault)
        return dict(result,format=repository.SCHEMA,repository=str(repo),attachments_closed=True,
                    capture_started=False,login_started=False,legacy_repositories_touched=False)


def restore(repo,snapshot,out):
    repo=legacy._parents(repo);out=legacy._parents(out)
    # Decode and authenticate actual source configuration BEFORE output creation.
    with repository.session(repo,readonly=True) as (db,owner):
        db.execute('BEGIN');manifest=repository.manifest(db,snapshot,owner)
        needed={'state/'+n for n in legacy._REQUIRED}|{'union/archive.wua.sqlite','union/OWNER.private.json'}
        repository.require(needed.issubset(manifest['files']),'incomplete state/union pair')
        entry=manifest['files']['state/config.private.json']
        repository.require(entry['bytes']<=1024*1024,'oversized source configuration')
        config=json.loads(b''.join(repository.Blocks(db).walk(entry['root'],entry['height'],entry['bytes'])))
        roots=legacy._source_roots(config)
        repository.require(roots==manifest['context']['source_roots'],'source configuration/protection differs')
        legacy._guard_location(out,legacy._external_root(manifest['context']['origin_state']),roots)
    manifest=repository.restore_files(repo,snapshot,out)
    state=out/'state';union=out/'union';state.mkdir(exist_ok=True)
    repository.require((state/'RESTORE.partial.private.json').is_file(),'missing partial state guard')
    for name in ('cache','reports','tmp'):(state/name).mkdir(exist_ok=True)
    state_manifest=dict(catalog_instance=manifest['owner']['catalog_instance'],source_roots=roots,
        files={n[6:]:e for n,e in manifest['files'].items() if n.startswith('state/')})
    state_result=legacy._verify_restored(state,state_manifest)
    with delivery._offline(state) as offline, CompactArchive(union/'archive.wua.sqlite') as archive:
        identity=archive._db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()
        repository.require(identity is not None and identity[0]==manifest['owner']['union_id'],'restored union identity differs')
        integrity=archive.integrity_check();assets=verify_union_assets(archive,offline,deep=True)
        from .viewer_media import verify as verify_media
        media=verify_media(archive,offline,deep=True)
        expected_media=manifest['context'].get('media_binding',dict(status='not_indexed',rows_verified=0))
        repository.require(media==expected_media,'restored native media binding differs')
        repository.require(integrity.get('quick_check')==['ok'] and not integrity.get('foreign_key_check') and
                           integrity.get('fts_verified') is True and assets.get('closure_complete') is True,
                           'restored union/attachment integrity failed')
        from .union_backup import _binding
        _,actual=_binding(assets,manifest['owner']['catalog_instance'],manifest['owner']['union_id'])
        _,expected=_binding(manifest['context']['asset_binding'],manifest['owner']['catalog_instance'],manifest['owner']['union_id'])
        repository.require(actual==expected,'restored attachment binding differs')
    for name,entry in manifest['files'].items():
        repository.require(digest_file(out/name)==entry['sha256'],'offline checks changed restored bytes')
    state_receipt=dict(schema=repository.SCHEMA,snapshot_id=snapshot,state='complete',verification=state_result,
                       includes_secrets=manifest['context']['includes_secrets'],offline=True)
    write_json_new(state/'RESTORE.complete.private.json',state_receipt)
    (state/'RESTORE.partial.private.json').unlink()
    result=dict(schema=repository.SCHEMA,format=repository.SCHEMA,snapshot_id=snapshot,receipt_root=str(out),
        state_restore=state_receipt,union_restore=dict(metadata_only=False,integrity=integrity,attachment_verification=assets,media_verification=media),
        restored_files={n:dict(sha256=e['sha256'],bytes=e['bytes']) for n,e in manifest['files'].items()},
        attachments_closed=True,referenced_cas_bytes_verified=True,capture_started=False,login_started=False,
        provenance_included=manifest['context']['provenance_included'],source_reconnected=False,phone_completeness=False)
    write_json_new(out/'DELIVERY.complete.private.json',result)
    return result
