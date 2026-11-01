"""Real cold-cut voice acceptance in an explicit disposable new fixture.

The source archive and decoded auxiliary databases remain read-only. Only an
evidence-selected voice subset is copied, never presented as a complete WUA.
All details stay in ignored working; stdout is aggregate only.
"""
import argparse
from collections import defaultdict,Counter
from contextlib import ExitStack,closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from wechat_capture_v2.common import digest_file,write_json_new
from wechat_capture_v2.objects import Objects
from .compact_archive import CompactArchive
from .union_archive import cold_input,cold_reader
from .union_delivery import _config
from . import viewer_media,media_preview


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('state','wua','target'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args(argv)
    from .paths import local_absolute
    a.state=local_absolute(a.state,allow_relative=True);a.wua=local_absolute(a.wua,allow_relative=True);a.target=local_absolute(a.target,allow_relative=True)
    if a.target.exists():raise FileExistsError('fresh owned media fixture required')
    a.target.mkdir();start=time.monotonic();config=_config(a.state)
    state=a.target/'state';state.mkdir();output=a.target/'output';output.mkdir()
    from types import SimpleNamespace
    service=SimpleNamespace(state=state,catalog=SimpleNamespace(path=state/'catalog.sqlite'),objects=None)
    result=dict(scope='cold_cut_voice_subset_not_complete_archive',formal_state_mutated=False)
    with ExitStack() as stack:
        stack.enter_context(cold_input(a.state/'catalog.sqlite'));stack.enter_context(cold_input(a.wua))
        catalog=stack.enter_context(closing(cold_reader(a.state/'catalog.sqlite')))
        source=stack.enter_context(CompactArchive(a.wua,readonly=True,immutable=True))
        service.catalog.db=stack.enter_context(closing(sqlite3.connect(service.catalog.path)))
        service.catalog.db.row_factory=sqlite3.Row
        instance=catalog.execute("SELECT value FROM meta WHERE key='next_catalog_instance'").fetchone()[0]
        service.catalog.db.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        service.catalog.db.execute("INSERT INTO meta VALUES('next_catalog_instance',?)",(instance,));service.catalog.db.commit()
        service.objects=stack.enter_context(closing(Objects(state/'objects.sqlite')))
        archive=stack.enter_context(CompactArchive(a.target/'voice-subset.sqlite',create=True))
        union=source._db.execute("SELECT value FROM archive_meta WHERE key='next_union_id'").fetchone()[0]
        archive._db.execute("INSERT INTO archive_meta VALUES('next_union_id',?)",(union,));archive._db.commit()
        imported=[];servers=set()
        for row in catalog.execute('''SELECT c.relative_path,d.id,d.evidence_json FROM checkpoint c
            JOIN db_capture d ON d.id=c.capture_id WHERE c.source_id=?''',(config['source_id'],)):
            relative=row[0]
            if not viewer_media.re.fullmatch(r'message/media_\d+\.db',relative):continue
            path=a.state/'cache'/(hashlib.sha256(relative.encode()).hexdigest()+'.db')
            imported.append(viewer_media.import_voice(archive,service,source_id=config['source_id'],account_alias=config['account_alias'],
                relative=relative,capture_id=row[1],evidence=json.loads(row[2]),path=path))
        servers={r[0] for r in archive._db.execute('SELECT server_id FROM next_media_voice WHERE server_id IS NOT NULL')}
        grouped=defaultdict(list);snapshots={};source_meta=None
        for row in source._db.execute('''SELECT o.*,s.metadata_json snapshot_meta,d.metadata_json source_meta
            FROM observation_record o JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id JOIN source_device d ON d.source_id=s.source_id
            WHERE s.source_id=? AND o.account_alias=? AND (CAST(o.message_type AS INTEGER)&4294967295)=34''',
            (config['source_id'],config['account_alias'])):
            if row['server_id'] not in servers:continue
            values=json.loads(source.pool.get_text(row['normalized_json']));values['raw_record']=json.loads(source.pool.get_text(row['raw_record_json']))
            grouped[row['snapshot_id']].append(values);snapshots[row['snapshot_id']]=json.loads(row['snapshot_meta'])
            source_meta=json.loads(row['source_meta'])
        for snapshot,rows in grouped.items():archive.import_observations(source_meta,snapshots[snapshot],rows)
        result['integrity']=viewer_media.verify(archive,service)
        counts=Counter();ready=[];selected=[]
        for row in archive._db.execute('SELECT logical_id FROM logical_record ORDER BY logical_id'):
            matched=viewer_media.for_message(archive,row[0]);counts[matched['status']]+=1
            for item in matched['rows']:
                if item['status']=='linked' and item['file_sha'] not in ready:
                    ready.append(item['file_sha']);selected.append((row[0],item))
        # Decode five distinct actual native voices; never auto-play audio or
        # export raw details. Full framing and target WAVE readback are checked.
        decoded=Counter()
        for logical,item in selected[:5]:
            try:
                preview=media_preview.prepare(archive,service.objects.db,output,logical_id=logical,snapshot_id=item['snapshot_id'],locator=item['locator'])
                binary=media_preview.read(output,preview['artifact_id'])
                if binary.content_type!='audio/wav' or not binary.data.startswith(b'RIFF'):raise ValueError('not WAVE')
                decoded['ready']+=1
            except Exception as error:decoded['error:'+type(error).__name__]+=1
        before=[d.total_changes for d in (archive._db,service.catalog.db,service.objects.db)]
        for row in catalog.execute('''SELECT c.relative_path,d.id,d.evidence_json FROM checkpoint c
            JOIN db_capture d ON d.id=c.capture_id WHERE c.source_id=?''',(config['source_id'],)):
            if not viewer_media.re.fullmatch(r'message/media_\d+\.db',row[0]):continue
            viewer_media.import_voice(archive,service,source_id=config['source_id'],account_alias=config['account_alias'],relative=row[0],
                capture_id=row[1],evidence=json.loads(row[2]),path=a.state/'cache'/(hashlib.sha256(row[0].encode()).hexdigest()+'.db'))
        result.update(imported_snapshots=len(imported),subset_observations=sum(map(len,grouped.values())),
            association_counts=dict(counts),distinct_linked_voices=len(ready),decoded_sample=dict(decoded),
            unchanged_reimport_db_changes=[d.total_changes-b for d,b in zip((archive._db,service.catalog.db,service.objects.db),before)])
    result.update(elapsed_seconds=time.monotonic()-start,fixture_total_bytes=sum(f.stat().st_size for f in a.target.rglob('*') if f.is_file()))
    write_json_new(a.target/'RESULT.private.json',result);print(json.dumps(result))


if __name__=='__main__':main()
