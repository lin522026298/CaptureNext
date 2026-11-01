"""Recoverable raw backups and complete-text exports, separate from legacy output."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3

from wua.store import ArchiveStore,_json as wua_json

from .common import canonical,digest_file,regular,safe_relative,source_files,utcnow,write_json_new


def backup(service, output, include_secrets=False):
    output = service.validate_output(output)
    if include_secrets and not (service.state/'90_SECRETS_PLAINTEXT_RESTRICTED'/'keyring.json').is_file():
        raise ValueError('this state has no keyring; create a keyless backup or explicitly import keys first')
    output.mkdir(parents=True,exist_ok=False)
    for name, db in (("catalog.sqlite",service.catalog.db),("objects.sqlite",service.objects.db)):
        target = sqlite3.connect(output/name)
        try:
            db.backup(target)
            if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("backup SQLite integrity failed")
        finally:
            target.close()
    if include_secrets:
        secret = output / "90_SECRETS_PLAINTEXT_RESTRICTED"
        secret.mkdir()
        with (service.state / "90_SECRETS_PLAINTEXT_RESTRICTED" / "keyring.json").open("rb") as original, (secret/"keyring.json").open("xb") as target:
            shutil.copyfileobj(original,target)
    report = {"schema":"capture-backup-1","created":utcnow(),"contains_plaintext_keys":bool(include_secrets),
              "keys_external_dependency":not include_secrets,"config":service.config,"files":[],
              "source_state":service.catalog.summary(),"message_and_media_association":"raw_assets_backed_up_not_all_linked"}
    for path in sorted(output.rglob("*")):
        if path.is_file():
            report["files"].append({"path":path.relative_to(output).as_posix(),"bytes":path.stat().st_size,"sha256":digest_file(path)})
    write_json_new(output / "MANIFEST.private.json",report)
    for row in report["files"]:
        if digest_file(output / row["path"]) != row["sha256"]:
            raise ValueError("backup manifest readback failed")
    return {"pass":True,"files":len(report["files"]),"contains_plaintext_keys":include_secrets}


def export_jsonl(service, path):
    path=service.validate_output(path)
    count = 0
    with Path(path).open("x",encoding="utf-8",newline="\n") as stream:
        for row in service.catalog.db.execute("SELECT id,source_id,account,relative_path,table_name,locator_json,row_hash,raw_z,normalized_json,first_capture FROM version ORDER BY id"):
            import zlib
            value = {"version_id":row[0],"source_id":row[1],"account_alias":row[2],"db_relative_path":row[3],
                     "table_name":row[4],"native_locator":json.loads(row[5]),"row_hash":row[6],
                     "raw_exact":json.loads(zlib.decompress(row[7])),"normalized":json.loads(row[8]),"first_capture":row[9]}
            value["interpretation_history"]=[{"normalization_hash":r[0],"normalized":json.loads(r[1]),"first_capture":r[2]}
                for r in service.catalog.db.execute("SELECT normalization_hash,normalized_json,first_capture FROM interpretation WHERE version_id=? ORDER BY first_capture,normalization_hash",(row[0],))]
            stream.write(canonical(value)+"\n")
            count += 1
    return {"rows":count,"body_truncation":False,"row_count_limit":None,"sha256":digest_file(path)}


def export_wua(service, path):
    path = service.validate_output(path)
    if path.exists():
        raise FileExistsError("export must not replace an existing archive")
    totals = {"captures":0,"observations":0}
    with ArchiveStore(path) as archive:
        # All versions are retained; WUA's existing conservative strong identity
        # logic supplies a separate logical/dedup layer, never an overwrite sink.
        captures = service.catalog.db.execute("""SELECT * FROM db_capture WHERE id IN
            (SELECT first_capture FROM version UNION SELECT first_capture FROM interpretation) ORDER BY rowid""")
        # The legacy public importer rebuilds the entire logical layer after
        # EVERY capture. A long-running collector has many tiny captures, so
        # repeating that operation makes export quadratic. This integration
        # uses the unchanged legacy row validator and exactly one rebuild,
        # exclusively inside this brand-new destination's transaction.
        archive._db.execute('BEGIN IMMEDIATE')
        try:
            for capture in captures:
                evidence = json.loads(capture["evidence_json"])
                source_meta={"source_id":capture["source_id"],"platform":"windows","kind":"capture-v2-raw-observations"}
                snapshot_meta={"snapshot_id":capture["id"],"source_id":capture["source_id"],
                    "basis":"authenticated-source-cut" if evidence.get('authentication') else 'explicit-frozen-plaintext-import',
                    "evidence_sha256":hashlib.sha256(capture["evidence_json"].encode()).hexdigest()}
                archive._db.execute('INSERT OR IGNORE INTO source_device VALUES(?,?)',
                                    (capture['source_id'],wua_json(source_meta)))
                archive._db.execute('INSERT INTO source_snapshot VALUES(?,?,?)',
                                    (capture['id'],capture['source_id'],wua_json(snapshot_meta)))
                import zlib
                from .common import decoded
                for row in service.catalog.db.execute("""SELECT raw_z,normalized_json FROM version WHERE first_capture=?
                    UNION ALL SELECT v.raw_z,i.normalized_json FROM interpretation i JOIN version v ON v.id=i.version_id
                    WHERE i.first_capture=?""",(capture["id"],capture["id"])):
                    item = json.loads(row["normalized_json"])
                    item["raw_record"] = decoded(json.loads(zlib.decompress(row["raw_z"])))
                    item["input_database_sha256"] = evidence["plaintext"]["sha256"]
                    if evidence.get("reader",{}).get("schema_sha256"):
                        item["input_schema_sha256"] = evidence["reader"]["schema_sha256"]
                    prepared=archive._prepare_row(capture['id'],item)
                    columns=','.join(prepared)
                    archive._db.execute('INSERT INTO message_observation ('+columns+') VALUES ('+
                                        ','.join('?' for _ in prepared)+')',tuple(prepared.values()))
                    totals['observations']+=1
                totals["captures"] += 1
            archive._rebuild()
            archive._db.execute('COMMIT')
        except BaseException:
            archive._db.execute('ROLLBACK')
            raise
        totals["stats"] = archive.stats()
        totals["integrity"] = archive.integrity_check()
        totals['pass']=(totals['integrity']['quick_check']==['ok'] and not totals['integrity']['foreign_key_check'])
        if not totals['pass']:
            raise ValueError('new WUA export integrity failed')
        totals["semantic_digest"] = archive.semantic_digest()
    return totals


def restore_backup(source,output):
    """Verify before copying; restore into a brand-new state, never live sources."""
    source=Path(source).resolve(strict=True)
    manifest=json.loads((source/'MANIFEST.private.json').read_text(encoding='utf-8'))
    if manifest.get('schema')!='capture-backup-1':
        raise ValueError('unsupported backup manifest')
    files={}
    allowed={'catalog.sqlite','objects.sqlite','90_SECRETS_PLAINTEXT_RESTRICTED/keyring.json'}
    for row in manifest['files']:
        relative=safe_relative(row['path'])
        if relative not in allowed or relative in files:
            raise ValueError('unexpected or duplicate backup entry')
        path=source/relative
        regular(path)
        if path.stat().st_size!=row['bytes'] or digest_file(path)!=row['sha256']:
            raise ValueError('backup hash/size verification failed')
        files[relative]=row
    if not {'catalog.sqlite','objects.sqlite'}.issubset(files):
        raise ValueError('backup missing required catalog or object database')
    if bool(manifest['contains_plaintext_keys']) != ('90_SECRETS_PLAINTEXT_RESTRICTED/keyring.json' in files):
        raise ValueError('backup key inventory does not match its declaration')
    output=Path(output).resolve()
    config=manifest['config']
    for key in ('database_root','asset_root'):
        if config.get(key):
            root=Path(config[key]).resolve()
            if output.is_relative_to(root) or root.is_relative_to(output):
                raise ValueError('restore output overlaps configured live source')
    output.mkdir(parents=True,exist_ok=False)
    for relative,row in files.items():
        target=output/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        with (source/relative).open('rb') as original,target.open('xb') as restored:
            shutil.copyfileobj(original,restored)
        if digest_file(target)!=row['sha256']:
            raise ValueError('restored hash readback failed')
    write_json_new(output/'config.private.json',config)
    for name in ('reports','tmp','cache'):
        (output/name).mkdir()
    return {'pass':True,'files_verified':len(files),'contains_plaintext_keys':manifest['contains_plaintext_keys'],
            'requires_external_keys':not manifest['contains_plaintext_keys'],'live_sources_modified':False}


def extract_assets(service,output):
    output=service.validate_output(output)
    output.mkdir(parents=True,exist_ok=False)
    count=total=0
    for relative,key,size in service.catalog.db.execute('SELECT relative_path,file_sha,bytes FROM asset WHERE source_id=? ORDER BY relative_path',
                                                        (service.config['source_id'],)):
        relative=safe_relative(relative)
        service.objects.restore(key,output/relative)
        count+=1
        total+=size
    return {'pass':True,'files_restored':count,'bytes_restored':total,'basis':'last_successfully_observed_asset_versions'}


def verify_asset_tree(service,root):
    root=Path(root).resolve(strict=True)
    actual={relative for relative,path in source_files(root)}
    expected=set()
    failures=[]
    total=0
    for relative,key,size in service.catalog.db.execute('SELECT relative_path,file_sha,bytes FROM asset WHERE source_id=? ORDER BY relative_path',
                                                        (service.config['source_id'],)):
        relative=safe_relative(relative)
        expected.add(relative)
        path=root/relative
        try:
            regular(path)
            if path.stat().st_size!=size or digest_file(path)!=key:
                raise ValueError('restored asset hash/size mismatch')
            total+=size
        except (OSError,ValueError):
            failures.append(hashlib.sha256(relative.encode()).hexdigest())
    return {'pass':not failures and actual==expected,'expected_files':len(expected),'actual_files':len(actual),
            'verified_bytes':total,'failed_files':len(failures),'unexpected_files':len(actual-expected),
            'failure_identifiers_hashed':failures}
