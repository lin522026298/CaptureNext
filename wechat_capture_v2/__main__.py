"""Independent CLI; never modifies the legacy tools, source DBs or frontend."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from .common import canonical,digest_file,utcnow,writer_lock
from .service import CaptureService,initialize


def concise(report):
    result={"cycle_id":report["cycle_id"],"status":report["status"],"mode":report["mode"],
            "elapsed_seconds":report["elapsed_seconds"],"databases_accepted":sum(r["status"]=="accepted" for r in report["databases"]),
            "databases_unchanged":sum(r["status"]=="unchanged_metadata" for r in report["databases"]),
            "databases_verified_unchanged":sum(r['status']=='verified_unchanged' for r in report['databases']),
            "new_versions":sum(r.get("new_versions",0) for r in report["databases"]),
            "rows_scanned":sum(r.get("rows",0) for r in report["databases"]),
            "error_count":len(report["errors"]),"summary":report["summary"]}
    if 'assets' in report:
        result['assets']={key:value for key,value in report['assets'].items() if key!='errors'}
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest="command",required=True)
    init=commands.add_parser("init",help="create independent private state; do not import/modify legacy archives")
    init.add_argument("--state",required=True,type=Path)
    init.add_argument("--database-root",required=True,type=Path)
    init.add_argument("--keyring",required=True,type=Path)
    init.add_argument("--source-id",required=True)
    init.add_argument("--account-alias",required=True)
    init.add_argument("--self-username")
    init.add_argument("--asset-root",type=Path)
    restore=commands.add_parser('restore-backup')
    restore.add_argument('--backup',required=True,type=Path)
    restore.add_argument('--out',required=True,type=Path)
    for name in ("capture","watch","stats","compare-legacy","backup","extract-db","export-jsonl","export-wua","import-plain","import-keyring","verify-state","extract-assets","verify-assets"):
        child=commands.add_parser(name)
        child.add_argument("--state",required=True,type=Path)
        if name in ("capture","watch"):
            child.add_argument("--assets",action="store_true",help="back up raw account assets as well as all databases")
            child.add_argument("--retries",type=int,default=3,help="transient file-race retries, NOT a history/message cap")
        if name=="capture":
            child.add_argument("--full",action="store_true",help="ignore metadata hints and reconcile every row in every readable DB")
        if name=="watch":
            child.add_argument("--interval",type=float,default=3.0)
            child.add_argument("--reconcile-seconds",type=float,default=300.0)
            child.add_argument("--assets-seconds",type=float,default=60.0)
            child.add_argument('--asset-budget-seconds',type=float,default=2.0,help='time slice per asset pass; never caps total files')
            child.add_argument("--run-seconds",type=float,help="optional observation-test duration; never caps history rows")
            child.add_argument('--stop-file',type=Path,help='cooperative stop at a complete capture boundary')
        if name in ("compare-legacy","backup","extract-db","export-jsonl","export-wua","extract-assets"):
            child.add_argument("--out",required=True,type=Path)
        if name=="backup":
            child.add_argument("--include-secrets",action="store_true",help="private LOCAL backup only; includes plaintext decryption keys")
        if name=="extract-db":
            child.add_argument("--relative-path",required=True)
        if name in ('import-plain','import-keyring'):
            child.add_argument('--input',required=True,type=Path)
        if name in ('verify-state','verify-assets'):
            child.add_argument('--out',type=Path,help='optional new JSON verification report')
        if name=='verify-assets':
            child.add_argument('--assets-root',required=True,type=Path)
    args=parser.parse_args(argv)
    if args.command=='restore-backup':
        from .export import restore_backup
        print(canonical(restore_backup(args.backup,args.out)))
        return 0
    if args.command=="init":
        initialize(args.state,args.database_root,args.keyring,source_id=args.source_id,
                   account_alias=args.account_alias,self_username=args.self_username,asset_root=args.asset_root)
        print(canonical({"initialized":True,"legacy_unchanged":True,"message_count_limit":None}))
        return 0
    with writer_lock(args.state):
        service=CaptureService(args.state)
        try:
            if args.command=="stats":
                result=service.catalog.summary()
            elif args.command=="capture":
                result=concise(service.capture(force=args.full,assets=args.assets,retries=args.retries))
            elif args.command=="watch":
                if args.interval<=0 or args.reconcile_seconds<=0 or args.assets_seconds<=0 or args.asset_budget_seconds<=0 or args.retries<1:
                    parser.error("positive polling/retry settings required")
                beginning=time.monotonic()
                last_full=last_assets=0.0
                asset_pending=False
                # Every start/restart reconciles fully, even if progress file was
                # lost; no 'start from latest' initialization can skip backlog.
                while True:
                    if args.stop_file and args.stop_file.exists():
                        break
                    now=time.monotonic()
                    full=last_full==0.0 or now-last_full>=args.reconcile_seconds
                    do_assets=args.assets and (asset_pending or last_assets==0.0 or now-last_assets>=args.assets_seconds)
                    report=service.capture(force=full,assets=do_assets,retries=args.retries,asset_budget_seconds=args.asset_budget_seconds,reuse_identical=True)
                    print(canonical(concise(report)),flush=True)
                    # A failed shard must not make all healthy shards perform
                    # a full scan every three seconds. Failed shards remain
                    # explicitly pending and retry in ordinary changed rounds.
                    if full:
                        last_full=time.monotonic()
                    if do_assets:
                        asset_pending=not report.get('assets',{}).get('complete',True)
                        if not asset_pending and not report.get("assets",{}).get("errors"):
                            last_assets=time.monotonic()
                    if args.run_seconds is not None and time.monotonic()-beginning>=args.run_seconds:
                        break
                    until=time.monotonic()+args.interval
                    while time.monotonic()<until:
                        if args.stop_file and args.stop_file.exists():
                            break
                        time.sleep(min(0.25,max(0,until-time.monotonic())))
                result={"watch_finished":True,"summary":service.catalog.summary()}
            elif args.command=="compare-legacy":
                from .compare import verify_legacy
                report=verify_legacy(service,args.out)
                result={key:report[key] for key in ("pass","expected_message_rows","matched_message_rows","comparison_scope","phone_completeness")}
            elif args.command=="backup":
                from .export import backup
                result=backup(service,args.out,args.include_secrets)
            elif args.command=="extract-db":
                service.validate_output(args.out)
                previous=service.catalog.checkpoint(service.config["source_id"],args.relative_path.replace("\\","/"))
                if previous is None:
                    raise ValueError("no captured database with that relative path")
                row=service.catalog.db.execute("SELECT evidence_json FROM db_capture WHERE id=?",(previous["capture_id"],)).fetchone()
                result=service.objects.restore(json.loads(row[0])["plaintext"]["sha256"],args.out)
            elif args.command=="export-jsonl":
                from .export import export_jsonl
                result=export_jsonl(service,args.out)
            elif args.command=='import-plain':
                from .imports import import_plain
                result=import_plain(service,args.input)
            elif args.command=='import-keyring':
                from .imports import import_keyring
                result=import_keyring(service,args.input)
            elif args.command=='verify-state':
                result=service.verify_state()
                if args.out:
                    from .common import write_json_new
                    service.validate_output(args.out)
                    write_json_new(args.out,result)
            elif args.command=='extract-assets':
                from .export import extract_assets
                result=extract_assets(service,args.out)
            elif args.command=='verify-assets':
                from .export import verify_asset_tree
                result=verify_asset_tree(service,args.assets_root)
                if args.out:
                    from .common import write_json_new
                    service.validate_output(args.out)
                    write_json_new(args.out,result)
            else:
                from .export import export_wua
                result=export_wua(service,args.out)
            print(canonical(result),flush=True)
            return 1 if result.get("pass") is False or result.get("status")=="partial" else 0
        finally:
            service.close()


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(canonical({"stopped":True,"restart_policy":"full_reconciliation"}),flush=True)
        raise SystemExit(130)
