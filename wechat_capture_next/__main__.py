"""Experimental changed-write collector; explicit independent state, no UI takeover."""
import argparse
from pathlib import Path
import time

from wechat_capture_v2.common import canonical
from .state_guard import writer_lock
from wechat_capture_v2.export import export_jsonl
from .service import CaptureService, initialize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init')
    init.add_argument('--state', required=True, type=Path)
    init.add_argument('--database-root', required=True, type=Path)
    init.add_argument('--keyring', required=True, type=Path)
    init.add_argument('--source-id', required=True)
    init.add_argument('--account-alias', required=True)
    init.add_argument('--self-username')
    init.add_argument('--asset-root', type=Path)
    restore = commands.add_parser('restore')
    restore.add_argument('--repository',type=Path,required=True)
    restore.add_argument('--snapshot-id',required=True)
    restore.add_argument('--out',type=Path,required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--state',type=Path,required=True)
    serve.add_argument('--output-root',type=Path,required=True)
    serve.add_argument('--repository-root',type=Path)
    serve.add_argument('--managed-root',type=Path)
    serve.add_argument('--port',type=int,default=0)
    union=commands.add_parser('union')
    union.add_argument('--state',type=Path,required=True)
    union.add_argument('--out',type=Path,required=True)
    union.add_argument('--input',nargs=2,action='append',metavar=('STABLE_ORIGIN','READONLY_WUA'),default=[])
    union.add_argument('--verify',action='store_true')
    for name in ('capture', 'watch', 'verify', 'stats', 'export-jsonl', 'export-wua', 'sync-wua', 'compact-evidence', 'report',
                 'backup','configure-assets','assets-inventory','export-asset','preview-asset','prune-unpublished'):
        child = commands.add_parser(name)
        child.add_argument('--state', type=Path, required=True)
        if name in ('capture', 'watch'):
            child.add_argument('--full', action='store_true')
            child.add_argument('--assets', action='store_true')
        if name == 'watch':
            child.add_argument('--interval', type=float, default=3)
            child.add_argument('--reconcile-seconds', type=float, default=300)
            child.add_argument('--run-seconds', type=float)
            child.add_argument('--stop-file', type=Path)
        if name in ('export-jsonl', 'export-wua', 'sync-wua', 'compact-evidence'):
            child.add_argument('--out', type=Path, required=True)
        if name == 'sync-wua':
            child.add_argument('--verify', action='store_true')
        if name == 'report':
            child.add_argument('--cycle-id', required=True)
        if name == 'backup':
            child.add_argument('--repository',type=Path,required=True)
            child.add_argument('--include-secrets',action='store_true')
        if name == 'configure-assets':
            child.add_argument('--root',type=Path,required=True)
        if name in ('export-asset','preview-asset'):
            child.add_argument('--sha',required=True)
            child.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    if args.command == 'init':
        values = vars(args).copy()
        values.pop('command')
        initialize(**values)
        print(canonical({'initialized': True, 'independent_state': True}))
        return
    if args.command == 'restore':
        from .backup import restore
        print(canonical(restore(args.repository,args.snapshot_id,args.out)))
        return
    if args.command == 'serve':
        from .console import main as console_main
        options = ['--state',str(args.state),'--output-root',str(args.output_root),'--port',str(args.port)]
        if args.repository_root is not None:
            options += ['--repository-root',str(args.repository_root)]
        if args.managed_root is not None:
            options += ['--managed-root',str(args.managed_root)]
        return console_main(options)
    with writer_lock(args.state):
        service = CaptureService(args.state)
        try:
            if args.command == 'stats':
                print(canonical(service.catalog.summary()))
            elif args.command == 'union':
                from .union_archive import sync_union
                print(canonical(sync_union(service,args.out,inputs=args.input,verify=args.verify)))
            elif args.command == 'report':
                print(service.catalog.report(args.cycle_id))
            elif args.command == 'compact-evidence':
                from .migrate_evidence import migrate
                print(canonical(migrate(service, args.out)))
            elif args.command == 'verify':
                print(canonical(service.verify_state()))
            elif args.command == 'backup':
                from .backup import backup
                print(canonical(backup(service,args.repository,include_secrets=args.include_secrets)))
            elif args.command == 'configure-assets':
                from .assets import configure_asset_root
                print(canonical(configure_asset_root(service,args.root)))
            elif args.command == 'assets-inventory':
                from .assets import inventory_assets
                print(canonical(inventory_assets(service)))
            elif args.command == 'prune-unpublished':
                from .assets import prune_unpublished
                print(canonical(prune_unpublished(service)))
            elif args.command in ('export-asset','preview-asset'):
                from .assets import export_asset, preview_asset
                operation = export_asset if args.command=='export-asset' else preview_asset
                print(canonical(operation(service,args.sha,args.out)))
            elif args.command == 'export-jsonl':
                print(canonical(export_jsonl(service, args.out)))
            elif args.command == 'export-wua':
                from .exports import export_wua
                print(canonical(export_wua(service, args.out)))
            elif args.command == 'sync-wua':
                from .sync_wua import sync_wua
                print(canonical(sync_wua(service, args.out, verify=args.verify)))
            elif args.command == 'capture':
                report = service.capture(force=args.full, assets=args.assets)
                print(canonical(report))
                return 0 if report['status'] == 'local_complete' else 2
            else:
                if args.interval <= 0 or args.reconcile_seconds <= 0:
                    parser.error('positive intervals required')
                began = time.monotonic()
                last_full = None
                while not args.stop_file or not args.stop_file.exists():
                    now = time.monotonic()
                    full = last_full is None or now-last_full >= args.reconcile_seconds
                    report = service.capture(force=full, assets=args.assets,
                        asset_budget_seconds=2 if args.assets else None, reuse_identical=True)
                    if full:
                        last_full = now
                    print(canonical(report), flush=True)
                    if args.run_seconds is not None and time.monotonic()-began >= args.run_seconds:
                        break
                    time.sleep(args.interval)
        finally:
            service.close()


if __name__ == '__main__':
    raise SystemExit(main())
