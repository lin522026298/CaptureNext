"""Shared explicit file/video actions for live and no-key offline queues."""
from contextlib import ExitStack,closing
import json
import re

from .console import _name
from .compact_archive import CompactArchive
from .union_archive import cold_reader
from .paths import local_absolute


PARAMETERS={'logical_id','sha','view','kind'}


def validate(params,*,export=False):
    if (not isinstance(params.get('logical_id'),str) or not 1<=len(params['logical_id'])<=200 or
        not isinstance(params.get('sha'),str) or not re.fullmatch('[0-9a-f]{64}',params['sha']) or
        params.get('view','current') not in ('current','restored') or params.get('kind') not in (None,'file','video')):
        raise ValueError('invalid attachment selection')
    if export:_name(params.get('name'))


def perform(core,action,params):
    from .file_media import verify,export
    from .backup import _source_roots
    with core.reader_gate,ExitStack() as stack:
        restored=params.get('view','current')=='restored'
        if restored and core.offline_view is None:raise ValueError('open a completed offline copy first')
        state=core.offline_view.state if restored else core.state
        root=core.offline_view.union if restored else core.union_root
        archive=stack.enter_context(CompactArchive(root/'archive.wua.sqlite',readonly=True,immutable=restored))
        archive._db.execute('BEGIN')
        if restored:
            catalog=stack.enter_context(closing(cold_reader(state/'catalog.sqlite')))
            objects=stack.enter_context(closing(cold_reader(state/'objects.sqlite')))
        else:catalog,objects=core.service.catalog.db,core.service.objects.db
        args={k:params[k] for k in ('logical_id','sha','kind') if k in params}
        if action=='verify_attachment':return verify(archive,catalog,objects,**args)
        if action=='prepare_attachment':return core.attachment_cache.prepare(archive,catalog,objects,**args)
        # Output is always a fresh, explicit owned filename, never an archived
        # path or an implicit system/open command. Restored inputs stay guarded.
        config=json.loads((state/'config.private.json').read_text(encoding='utf-8'))
        protected=[state,root,*_source_roots(config)]
        if config.get('database_root'):protected.append(local_absolute(config['database_root']).parent)
        return export(archive,catalog,objects,destination=core.output_root/_name(params['name']),
            protected_roots=protected,**args)
