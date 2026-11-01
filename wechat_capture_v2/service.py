"""One backend for raw backup, authenticated extraction and continuous repair."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time

from .cipher import materialize
from .common import canonical, digest_file, directory, safe_relative, source_files, stamp, utcnow, write_json_new
from .objects import Objects,PendingImport
from .planner import changed_tables
from .source import capture_pair, copy_prefix,verify_unchanged_pair
from .store import Catalog
from wua import weixin4 as reader_module
from . import store as store_module


def load_config(state):
    state = Path(state).resolve(strict=True)
    config = json.loads((state / "config.private.json").read_text(encoding="utf-8"))
    source=Path(config['database_root'])
    if source.exists():
        directory(source)
    root = source.resolve()
    if state.is_relative_to(root) or root.is_relative_to(state):
        raise ValueError("state and source database roots must not overlap")
    if config.get("asset_root"):
        asset_path=Path(config['asset_root'])
        if asset_path.exists():
            directory(asset_path)
        assets = asset_path.resolve()
        if state.is_relative_to(assets) or assets.is_relative_to(state):
            raise ValueError("state and source asset roots must not overlap")
    return config


def initialize(state, database_root, keyring, *, source_id, account_alias, self_username=None, asset_root=None):
    state, database_root = Path(state).resolve(), directory(database_root).resolve(strict=True)
    if state.exists():
        raise FileExistsError("new independent state directory required")
    asset_root = directory(asset_root).resolve(strict=True) if asset_root else None
    for root in (database_root, asset_root):
        if root and (state.is_relative_to(root) or root.is_relative_to(state)):
            raise ValueError("state and source roots must not overlap")
    # Keys are copied only to private local state, never into exported reports.
    payload = json.loads(Path(keyring).read_text(encoding="utf-8-sig"))
    if not payload.get("databases"):
        raise ValueError("keyring has no database entries")
    state.mkdir(parents=True)
    secret = state / "90_SECRETS_PLAINTEXT_RESTRICTED"
    secret.mkdir()
    os.chmod(secret, 0o700)
    with Path(keyring).open("rb") as source, (secret / "keyring.json").open("xb") as target:
        shutil.copyfileobj(source, target)
    config = {"schema":"wechat-capture-v2-config-1","database_root":str(database_root),
              "asset_root":str(asset_root) if asset_root else None,"source_id":source_id,
              "account_alias":account_alias,"self_username":self_username,
              "message_count_limit":None,"history_time_limit":None,"created":utcnow()}
    write_json_new(state / "config.private.json", config)
    (state / "reports").mkdir()
    (state / "tmp").mkdir()
    (state / "cache").mkdir()
    return config


class CaptureService:
    def __init__(self, state):
        self.state = Path(state).resolve(strict=True)
        self.config = load_config(self.state)
        self.root = Path(self.config["database_root"])
        self.catalog = Catalog(self.state / "catalog.sqlite")
        self.objects = Objects(self.state / "objects.sqlite")
        # A process killed without finally cannot leave a successful cycle.
        # The CLI owns the OS writer lock before constructing this service.
        with self.catalog.db:
            self.catalog.db.execute("UPDATE cycle SET status='interrupted' WHERE status='running'")
        binding=canonical({key:self.config.get(key) for key in ("source_id","account_alias","self_username","database_root","asset_root")})
        with self.catalog.db:
            self.catalog.db.execute("INSERT OR IGNORE INTO meta VALUES('source_binding',?)",(binding,))
        if self.catalog.db.execute("SELECT value FROM meta WHERE key='source_binding'").fetchone()[0] != binding:
            raise ValueError("source/account configuration changed; create a new explicit state")
        self.load_keys()
        self._asset_iterator=None
        self._asset_force=False
        self._pending_asset=None
        self._asset_retry={}
        self._failed_databases=set()
        self._retry_schedule={}
        self._global_retry_at=0.0
        self._global_failures=0
        self._global_error=None
        self._summary_cache=self.catalog.summary()
        self.interpretation_binding=hashlib.sha256(canonical({'reader_sha256':digest_file(reader_module.__file__),
            'normalizer_sha256':digest_file(store_module.__file__),
            'cipher_sha256':digest_file(Path(__file__).with_name('cipher.py')),
            'source_protocol_sha256':digest_file(Path(__file__).with_name('source.py')),
            'source_binding':binding}).encode()).hexdigest()

    def load_keys(self):
        path=self.state / '90_SECRETS_PLAINTEXT_RESTRICTED' / 'keyring.json'
        # Existing plaintext/object backups can be inspected on an offline PC
        # without either the original client tree or plaintext encryption keys.
        payload = json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {'databases':[]}
        keys = {}
        for item in payload.get("databases", []):
            if item.get("verified") and item.get("raw_encryption_key_hex"):
                relative = safe_relative(item["relative_path"])
                if relative in keys:
                    raise ValueError("duplicate normalized key entry")
                key = bytes.fromhex(item["raw_encryption_key_hex"])
                if len(key) != 32:
                    raise ValueError("unsupported key entry")
                keys[relative] = key
        self.keys = keys

    def databases(self):
        return {relative: path for relative, path in source_files(self.root) if path.suffix.casefold() == ".db"}

    def validate_output(self,path):
        output=Path(path).resolve()
        for root in (self.root,Path(self.config['asset_root']) if self.config.get('asset_root') else None):
            if root and (output.is_relative_to(root) or root.is_relative_to(output)):
                raise ValueError('output must not overlap any configured live-source tree')
        if output.exists():
            raise FileExistsError('a new output path is required; existing deliverables are never overwritten')
        return output

    def _stamp(self, path):
        wal = Path(str(path) + "-wal")
        return {"main":stamp(path),"wal":stamp(wal) if wal.exists() else None}

    def capture(self, *, force=False, assets=False, retries=3, asset_budget_seconds=None,reuse_identical=False):
        """A full scan has no row cap. A transient file race never advances its checkpoint."""
        if retries < 1:
            raise ValueError('at least one acquisition attempt is required')
        started = time.monotonic()
        if not force and self._global_error and started<self._global_retry_at:
            return {'cycle_id':None,'status':'partial','mode':'retry_wait','started':utcnow(),'finished':utcnow(),
                'elapsed_seconds':0,'databases':[],'errors':[self._global_error],
                'summary':self._summary_cache,'persistent_evidence_written':False}
        if self._global_error:
            force=True  # Close an unavailable-source interval with content reconciliation.
        # No evidence is created by an idle poll. Coalescing these metadata-only
        # observations does not remove message versions, failures or source cuts.
        if not force and not assets:
            try:
                inventory=self.databases()
                known={row[0] for row in self.catalog.db.execute('SELECT relative_path FROM checkpoint WHERE source_id=?',(self.config['source_id'],))}
                same=bool(inventory) and (known|self._failed_databases)==set(inventory)
                for relative,path in inventory.items():
                    if relative in self._failed_databases:
                        pending=self._retry_schedule.get(relative)
                        if not pending or started>=pending['at']:
                            same=False;break
                        continue
                    previous=self.catalog.checkpoint(self.config['source_id'],relative)
                    if not previous or json.loads(previous['stamp_json'])!=json.loads(canonical(self._stamp(path))):
                        same=False;break
                if same and set(self.databases())==set(inventory):
                    return {'cycle_id':None,'status':'partial' if self._failed_databases else 'idle',
                        'mode':'retry_wait' if self._failed_databases else 'metadata_poll','started':utcnow(),'finished':utcnow(),
                        'elapsed_seconds':round(time.monotonic()-started,3),'databases':[
                            {'relative_path':relative,'status':'unchanged_metadata'} for relative in sorted(inventory)],
                        'errors':[{'relative_path':r,'error_type':'retry_backoff','checkpoint_advanced':False}
                                  for r in sorted(self._failed_databases)],'summary':self._summary_cache,'persistent_evidence_written':False,
                        'coverage':'local_pc_database_only_phone_completeness_unverified'}
            except (OSError,ValueError):
                pass
        cycle = self.catalog.begin_cycle("full_reconciliation" if force else "changed_shards")
        report = {"schema":"wechat-capture-cycle-1","cycle_id":cycle,"started":utcnow(),
                  "status":"running","mode":"full_reconciliation" if force else "changed_shards",
                  "message_count_limit":None,"history_time_limit":None,"databases":[],"errors":[],
                  "coverage":"local_pc_database_only_phone_completeness_unverified"}
        try:
            databases = self.databases()
            if not databases:
                raise ValueError('configured source contains no database files')
            known_before={row[0] for row in self.catalog.db.execute('SELECT relative_path FROM checkpoint WHERE source_id=?',(self.config['source_id'],))}
            if known_before.issubset(databases):
                self._global_error=None
                self._global_retry_at=0.0
                self._global_failures=0
            for relative, path in sorted(databases.items()):
                previous = self.catalog.checkpoint(self.config["source_id"], relative)
                current_stamp = self._stamp(path)
                if not force and relative in self._retry_schedule and time.monotonic()<self._retry_schedule[relative]['at']:
                    report['errors'].append({'relative_path':relative,'error_type':'retry_backoff',
                        'checkpoint_advanced':False,'retry_in_seconds':round(self._retry_schedule[relative]['at']-time.monotonic(),1)})
                    continue
                if not force and relative not in self._failed_databases and previous and json.loads(previous["stamp_json"]) == json.loads(canonical(current_stamp)):
                    report["databases"].append({"relative_path":relative,"status":"unchanged_metadata","capture_id":previous["capture_id"]})
                    continue
                if reuse_identical and previous:
                    prior=json.loads(self.catalog.db.execute('SELECT evidence_json FROM db_capture WHERE id=?',(previous['capture_id'],)).fetchone()[0])
                    proof=verify_unchanged_pair(path,prior) if prior.get('interpretation_binding')==self.interpretation_binding else None
                    if proof:
                        report['databases'].append({'relative_path':relative,'status':'verified_unchanged',
                            'capture_id':previous['capture_id'],'content_proof':proof})
                        self._failed_databases.discard(relative)
                        self._retry_schedule.pop(relative,None)
                        continue
                if relative not in self.keys:
                    report["errors"].append({"relative_path":relative,"error_type":"missing_key","checkpoint_advanced":False})
                    self._failed_databases.add(relative)
                    old=self._retry_schedule.get(relative,{}).get('failures',0)+1
                    self._retry_schedule[relative]={'failures':old,'at':time.monotonic()+min(60,3*2**min(old-1,5))}
                    continue
                error = None
                for attempt in range(1, retries + 1):
                    with tempfile.TemporaryDirectory(prefix="capture-", dir=self.state / "tmp") as work:
                        work = Path(work)
                        try:
                            pair = capture_pair(path, work / "source")
                            raw = {"main":self.objects.add(pair["main"])}
                            if pair["raw_wal"] is not None:
                                raw["wal_raw"] = self.objects.add(pair["raw_wal"])
                                raw["wal_committed"] = self.objects.add(pair["wal"])
                            # Even equal committed signatures may have different raw WAL tails;
                            # record successful full captures during explicit reconciliation.
                            plain = work / "plain.db"
                            auth = materialize(pair["main"], plain, self.keys[relative], pair["wal"])
                            plain_object = self.objects.add(plain)
                            cache = self.state / "cache" / (hashlib.sha256(relative.encode()).hexdigest() + ".db")
                            plan={"tables":None,"reason":"full_reconciliation","changed_pages":None}
                            if not force and previous and cache.is_file() and auth["structured_readable"]:
                                old_evidence=json.loads(self.catalog.db.execute("SELECT evidence_json FROM db_capture WHERE id=?",(previous["capture_id"],)).fetchone()[0])
                                if digest_file(cache)==old_evidence.get("plaintext",{}).get("sha256"):
                                    plan=changed_tables(cache,plain)
                            evidence = {"raw":raw,"plaintext":plain_object,"authentication":auth,
                                        'interpretation_binding':self.interpretation_binding,
                                        "wal_capture":pair["wal_capture"],"source_read_only":True,
                                        "time":utcnow(),"origin":"live_files","scan_plan":plan}
                            if auth["structured_readable"]:
                                outcome = self.catalog.ingest(cycle=cycle,source_id=self.config["source_id"],
                                    account=self.config["account_alias"],relative=relative,path=plain,evidence=evidence,
                                    signature=pair["signature"],stamp_value=current_stamp,
                                    self_username=self.config.get("self_username"),selected_tables=plan["tables"])
                            else:
                                if Path(relative).parent.name == "message" and not Path(relative).stem.endswith("_fts"):
                                    raise ValueError("message shard has no supported structured reader; checkpoint not advanced")
                                outcome = self.catalog.raw_only(cycle=cycle,source_id=self.config["source_id"],
                                    relative=relative,signature=pair["signature"],evidence=evidence,stamp_value=current_stamp)
                            # Mutable cache is only a convenience derivative. CAS above retains
                            # every accepted immutable generation, including the raw inputs.
                            cache_warning = None
                            try:
                                os.replace(plain, cache)
                            except OSError as exc:
                                cache_warning = type(exc).__name__
                            report["databases"].append({"relative_path":relative,"status":"accepted",
                                "attempts":attempt,"plaintext_sha256":plain_object["sha256"],
                                "optional_cache_warning":cache_warning,**outcome})
                            error = None
                            self._failed_databases.discard(relative)
                            self._retry_schedule.pop(relative,None)
                            break
                        except Exception as exc:
                            error = {"relative_path":relative,"error_type":type(exc).__name__,
                                     "detail_private":str(exc),"attempts":attempt,"checkpoint_advanced":False}
                    if attempt < retries:
                        time.sleep(0.1)
                if error:
                    report["errors"].append(error)
                    self._failed_databases.add(relative)
                    old=self._retry_schedule.get(relative,{}).get('failures',0)+1
                    self._retry_schedule[relative]={'failures':old,'at':time.monotonic()+min(60,3*2**min(old-1,5))}
            if set(self.databases()) != set(databases):
                report["errors"].append({"error_type":"database_inventory_changed","checkpoint_advanced":False})
            known = {r[0] for r in self.catalog.db.execute("SELECT relative_path FROM checkpoint WHERE source_id=?", (self.config["source_id"],))}
            absent = sorted(known - set(databases))
            if absent:
                self._global_error={"error_type":"previous_databases_missing","relative_paths":absent,"checkpoint_advanced":False}
                self._global_failures+=1
                self._global_retry_at=time.monotonic()+min(60,3*2**min(self._global_failures-1,5))
                report["errors"].append(self._global_error)
            if assets:
                report["assets"] = self.capture_assets(cycle, force=force,budget_seconds=asset_budget_seconds)
                if report["assets"]["errors"]:
                    report["errors"].append({"error_type":"asset_files_unstable_or_unreadable","count":len(report["assets"]["errors"])})
            report["status"] = "partial" if report["errors"] else "local_complete"
            if report['status']=='local_complete' and assets and not report['assets'].get('complete',True):
                report['status']='local_complete_assets_pending'
        except Exception as exc:
            report['status']='partial'
            self._global_error={'error_type':type(exc).__name__,'detail_private':str(exc),'checkpoint_advanced':False}
            self._global_failures+=1
            self._global_retry_at=time.monotonic()+min(60,3*2**min(self._global_failures-1,5))
            report['errors'].append(self._global_error)
        except BaseException:
            report["status"] = "interrupted"
            raise
        finally:
            report["finished"] = utcnow()
            report["elapsed_seconds"] = round(time.monotonic() - started, 3)
            # Finalize before taking status counts; the current successful cycle
            # must not be reported as an interrupted/running predecessor.
            report["summary"] = self.catalog.summary(ignore_cycle=cycle)
            self._summary_cache=report['summary']
            self.catalog.finish_cycle(cycle, report)
            write_json_new(self.state / "reports" / (cycle + ".json"), report)
        return report

    def capture_assets(self, cycle, force=False,budget_seconds=None):
        if not self.config.get("asset_root"):
            return {"enabled":False,"errors":[],"files_seen":0,"new_versions":0,'complete':True}
        root = Path(self.config["asset_root"])
        result = {"enabled":True,"errors":[],"files_seen":0,"new_versions":0,"bytes_seen":0,'complete':True}
        if budget_seconds is not None and budget_seconds<=0:
            raise ValueError('asset time slice must be positive')
        if budget_seconds is None:
            iterator=iter(source_files(root))
            pass_force=force
        else:
            if self._asset_iterator is None:
                self._asset_iterator=iter(source_files(root))
                self._asset_force=force
            iterator=self._asset_iterator
            pass_force=self._asset_force
        started=time.monotonic()
        attempted=0
        while True:
            # Cooperative scheduling, no total file/history cap. Disk stalls
            # cannot be bounded by a Python scheduling deadline.
            if attempted and budget_seconds is not None and time.monotonic()-started>=budget_seconds:
                result['complete']=False
                break
            try:
                if self._pending_asset is not None:
                    relative,path,pending=self._pending_asset
                else:
                    relative,path=next(iterator)
                    pending=None
            except StopIteration:
                if budget_seconds is not None:
                    self._asset_iterator=None
                break
            except Exception as exc:
                result['errors'].append({'error_type':type(exc).__name__,'detail_private':str(exc),'phase':'asset_walk'})
                result['complete']=False
                self._asset_iterator=None
                break
            attempted+=1
            if path.is_relative_to(self.root):
                continue  # Database+WAL acquisition has its stronger separate protocol.
            result["files_seen"] += 1
            try:
                if self._asset_retry.get(relative,0)>time.monotonic():
                    result['errors'].append({'path':relative,'error_type':'asset_retry_backoff'})
                    continue
                before = stamp(path)
                result["bytes_seen"] += before[2]
                old = self.catalog.db.execute("SELECT * FROM asset WHERE source_id=? AND relative_path=?",
                            (self.config["source_id"],relative)).fetchone()
                if not pass_force and old and old["stamp_json"] == canonical(before):
                    continue
                if budget_seconds is None:
                    obj = self.objects.add(path)
                    if digest_file(path) != obj['sha256'] or stamp(path) != before:
                        raise RuntimeError('asset changed during verification')
                else:
                    pending=pending or PendingImport(self.objects,path)
                    self._pending_asset=(relative,path,pending)
                    deadline=started+budget_seconds
                    obj=pending.advance(deadline)
                    # Small files may finish all phases in the same slice; do
                    # not turn 33,800 tiny files into 3 polling rounds each.
                    while obj is None and time.monotonic()<deadline:
                        obj=pending.advance(deadline)
                    if obj is None:
                        result.update(complete=False,pending_phase=pending.phase,pending_bytes=pending.size,
                            pending_processed_bytes=pending.offset,pending_chunks=len(pending.chunks))
                        break
                    before=pending.before
                    if stamp(path)!=before:
                        raise RuntimeError('asset changed after object publication')
                    self._pending_asset=None
                with self.catalog.db:
                    inserted = self.catalog.db.execute("INSERT OR IGNORE INTO asset_history VALUES(?,?,?,?,?)",
                        (self.config["source_id"],relative,obj["sha256"],obj["bytes"],cycle)).rowcount
                    self.catalog.db.execute("""INSERT INTO asset VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,relative_path)
                        DO UPDATE SET file_sha=excluded.file_sha,bytes=excluded.bytes,stamp_json=excluded.stamp_json,cycle_id=excluded.cycle_id""",
                        (self.config["source_id"],relative,obj["sha256"],obj["bytes"],canonical(before),cycle))
                result["new_versions"] += inserted
                self._asset_retry.pop(relative,None)
            except Exception as exc:
                self._pending_asset=None
                self._asset_retry[relative]=time.monotonic()+60
                result["errors"].append({"path":relative,"error_type":type(exc).__name__,"detail_private":str(exc)})
        return result

    def close(self):
        self.catalog.close()
        self.objects.close()

    def verify_state(self):
        for db in (self.catalog.db,self.objects.db):
            if [r[0] for r in db.execute('PRAGMA quick_check')]!=['ok']:
                raise ValueError('state SQLite integrity failed')
        if list(self.catalog.db.execute('PRAGMA foreign_key_check')):
            raise ValueError('catalog foreign-key integrity failed')
        references=set()
        for row in self.catalog.db.execute('SELECT evidence_json FROM db_capture'):
            evidence=json.loads(row[0])
            references.update(value['sha256'] for value in evidence.get('raw',{}).values())
            for key in ('plaintext','source_manifest'):
                if evidence.get(key):
                    references.add(evidence[key]['sha256'])
        references.update(row[0] for row in self.catalog.db.execute('SELECT file_sha FROM asset_history'))
        known={row[0] for row in self.objects.db.execute('SELECT hash FROM file')}
        if references-known:
            raise ValueError('catalog references missing backup objects')
        result=self.objects.verify_all()
        result['referenced_objects_verified']=len(references)
        return result
