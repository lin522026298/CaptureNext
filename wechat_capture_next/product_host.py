"""Private desktop endpoint plus independent optional WebUI, one shared core."""
import argparse
from contextlib import closing
import json
import sqlite3
from pathlib import Path
import sys
import threading

from .console import ConsoleServer, read_api, _page
from .compact_archive import CompactArchive
from .product import ProductCore


def product_read(core, path, query):
    if path == '/api/product':
        return core.control_snapshot()
    if path == '/api/jobs':
        return core.jobs_snapshot()
    if path=='/api/media':
        from .media_preview import read
        return read(core.output_root,query.get('id',[''])[0])
    if path=='/api/image':return core.image_cache.read(query.get('id',[''])[0])
    if path=='/api/attachment-preview':return core.attachment_cache.read(query.get('id',[''])[0])
    recovery=core.control_snapshot().get('product',{}).get('mode')=='recovery'
    if recovery and path not in ('/api/union-messages','/api/conversations','/api/message-detail','/api/message-context','/api/union-backups','/api/image-candidates','/api/attachment-candidates','/api/assets'):
        raise ValueError('route unavailable without a live state')
    if recovery and path!='/api/union-backups' and query.get('view',['current'])[0]!='restored':
        raise ValueError('select the explicit offline restored copy')
    if not core.reader_gate.acquire(blocking=False):
        raise BlockingIOError('maintenance; database readers temporarily paused')
    try:
        if core.maintenance:
            raise BlockingIOError('maintenance; database readers temporarily paused')
        if path=='/api/assets':
            from .raw_assets import read
            return read(core,query)
        if path == '/api/union-messages':
            limit,offset = _page(query)
            q = query.get('q',[''])[0]
            if len(q)>1000:
                raise ValueError('query too long')
            root=core.union_root
            if query.get('view',['current'])[0]=='restored':
                if core.offline_view is None:raise ValueError('open a completed restore first')
                root=core.offline_view.union
            elif query.get('view',['current'])[0]!='current':raise ValueError('unknown view')
            with CompactArchive(root/'archive.wua.sqlite',readonly=True,immutable=root!=core.union_root) as archive:
                archive._db.execute('BEGIN')
                from .viewer import messages
                filters={k:query[k][0] for k in ('account_alias','conversation_id','sender_id','message_type','since','until') if query.get(k,[''])[0]}
                flags={}
                for key in ('null_account','null_conversation'):
                    value=query.get(key,['0'])[0]
                    if value not in ('0','1'):raise ValueError('invalid null scope')
                    flags[key]=value=='1'
                return messages(archive,limit=limit,offset=offset,search=q or None,**flags,**filters)
        if path in ('/api/conversations','/api/message-detail','/api/message-context','/api/image-candidates','/api/attachment-candidates'):
            from . import viewer
            root=core.union_root
            if query.get('view',['current'])[0]=='restored':
                if core.offline_view is None:raise ValueError('open a completed restore first')
                root=core.offline_view.union
            elif query.get('view',['current'])[0]!='current':raise ValueError('unknown view')
            with CompactArchive(root/'archive.wua.sqlite',readonly=True,immutable=root!=core.union_root) as archive:
                archive._db.execute('BEGIN')
                if path=='/api/conversations':
                    limit,offset=_page(query);q=query.get('q',[''])[0]
                    if len(q)>1000:raise ValueError('query too long')
                    return viewer.conversations(archive,limit=limit,offset=offset,search=q)
                ident=query.get('id',[''])[0]
                if not isinstance(ident,str) or len(ident)>200:raise ValueError('message identity required')
                if path=='/api/message-context':return viewer.context(archive,ident)
                offset=int(query.get('offset',['0'])[0])
                if not 0<=offset<=2**63-1:raise ValueError('invalid candidate page')
                from .image_media import candidates
                from .console import _file
                restored=root!=core.union_root
                state=core.offline_view.state if restored else core.state
                catalog_path=state/'catalog.sqlite';_file(catalog_path)
                with closing(sqlite3.connect(catalog_path.as_uri()+'?mode=ro'+('&immutable=1' if restored else ''),uri=True)) as catalog:
                    catalog.row_factory=sqlite3.Row;catalog.execute('PRAGMA query_only=ON');catalog.execute('BEGIN')
                    from .file_media import candidates as attachment_candidates
                    if path=='/api/attachment-candidates':return attachment_candidates(archive,catalog,ident,after=query.get('after',[''])[0])
                    images=candidates(archive,catalog,ident,after=query.get('after',[''])[0])
                    attachments=attachment_candidates(archive,catalog,ident) if path=='/api/message-detail' else None
                if path=='/api/image-candidates':return images
                result=viewer.detail(archive,ident,candidate_offset=offset);result['images']=images;result['attachments']=attachments;return result
        if path == '/api/union-backups':
            from .backup_listing import listing
            return listing(core)
        return read_api(core,path,query)
    finally:
        core.reader_gate.release()


class ProductHost:
    def __init__(self, core):
        self.core = core
        self.lock = threading.RLock()
        self.browser = None
        self._closing = False
        self.desktop = self._listener()
        core.endpoint_control = self.set_webui
        if core.settings['webui_on_start']:
            self.set_webui(True)

    def _listener(self):
        server = ConsoleServer(self.core,0,owns_coordinator=False,
            web_root=Path(__file__).with_name('product_web'))
        server.read_api = product_read
        server.query_parameters={'q','limit','offset','view','id','after','account_alias','conversation_id','sender_id','message_type','since','until','null_account','null_conversation'}
        thread = threading.Thread(target=server.serve_forever,
            kwargs={'poll_interval':.1},name='next-ui-listener',daemon=True)
        thread.start()
        return server,thread

    @staticmethod
    def _stop(listener):
        server,thread = listener
        server.shutdown()
        server.server_close()
        thread.join()

    def set_webui(self, enabled):
        with self.lock:
            if self._closing:
                raise RuntimeError('host closing')
            if enabled and self.browser is None:
                self.browser = self._listener()
            elif not enabled and self.browser is not None:
                old,self.browser = self.browser,None
                self._stop(old)
            return dict(enabled=self.browser is not None,
                url=self.browser[0].base_url if self.browser else None)

    def close(self):
        # Do not hold endpoint lock while joining the writer: it may be inside
        # set_webui. Mark closing, then serialize safe worker shutdown first.
        with self.lock:
            self._closing = True
        self.core.close()
        with self.lock:
            for listener in (self.browser,self.desktop):
                if listener is not None:
                    self._stop(listener)
            self.browser = self.desktop = None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--state',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--union',type=Path)
    parser.add_argument('--state-repo',type=Path)
    parser.add_argument('--union-repo',type=Path)
    parser.add_argument('--paired-repo',type=Path)
    parser.add_argument('--provenance',type=Path)
    parser.add_argument('--offline',type=Path)
    parser.add_argument('--recovery',action='store_true')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    base = root/'archives'/'wechat-next'
    host = core = None
    try:
        from .recovery_core import RecoveryCore,active_binding,binding_lock
        common=dict(state=args.state or base/'state',union_root=args.union or base/'unified',
            repository_root=args.state_repo or base/'backups'/'state',union_repository=args.union_repo or base/'backups'/'unified',
            paired_repository=args.paired_repo or base/'backups'/'paired-v3')
        if args.offline is not None or args.recovery:
            core=RecoveryCore(base,**common,offline=args.offline)
        else:
            try:
                with binding_lock(base):
                    binding=active_binding(base)
                    options=dict(common,output_root=args.output or base/'product',provenance_root=args.provenance or base/'provenance')
                    if binding:
                        if any(v is not None for v in (args.state,args.union,args.output,args.provenance)):
                            raise ValueError('explicit paths conflict with active recovered binding')
                        options.update(binding)
                    if args.provenance is None and not (binding and 'provenance_root' in binding):
                        from .first_run import default_provenance
                        options['provenance_root']=default_provenance(options['state'],base)
                    core=ProductCore(**options)
            except Exception as error:
                core=RecoveryCore(base,**common,reason='formal_startup_unavailable_'+type(error).__name__)
        host = ProductHost(core)
        server = host.desktop[0]
        print(json.dumps(dict(url=server.base_url,token=server.token,mode=core.control_snapshot()['product']['mode'])),flush=True)
        # Parent-owned redirected pipe. EOF/crashed shell => safe core close.
        for line in sys.stdin:
            if line.strip() == 'quit':
                break
        return 0
    except Exception as error:
        # No configuration, token, query, path or chat text in diagnostics.
        print(json.dumps(dict(error_type=type(error).__name__)),file=sys.stderr,flush=True)
        return 1
    finally:
        if host is not None:
            host.close()
        elif core is not None:
            core.close()


if __name__ == '__main__':
    raise SystemExit(main())
