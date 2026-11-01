"""Cold read-only long-conversation acceptance; aggregate metrics only.

No message text, names, account/source/message identifiers or dates are emitted.
This checks the retained union viewer, never whole-phone history completeness.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time

import psutil

from wechat_capture_v2.common import write_json_new
from .product_settings import atomic_json
from . import viewer
from .compact_archive import CompactArchive, HEAVY_CACHE_KIB
from .paths import local_absolute
from .state_guard import writer_lock
from .union_archive import cold_input
from .union_delivery import _offline, _formal, _instance


def _require(value):
    if not value:raise ValueError('viewer aggregate acceptance invariant failed')


def _source_provenance():
    root=Path(__file__).resolve().parents[1]
    names=('benchmark_viewer','viewer','viewer_access','viewer_identity','viewer_media','compact_archive','content_pool')
    paths=[Path(__file__).with_name(name+'.py') for name in names]
    flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
    revision=subprocess.run(['git','rev-parse','HEAD'],cwd=root,capture_output=True,text=True,check=True,creationflags=flags).stdout.strip()
    dirty=subprocess.run(['git','status','--porcelain','--',*[str(p.relative_to(root)) for p in paths]],
        cwd=root,capture_output=True,text=True,check=True,creationflags=flags).stdout.strip()
    return dict(git_revision=revision,measured_sources_dirty=bool(dirty),
        sha256={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})


@contextmanager
def _measurement(result):
    process=psutil.Process();start=time.monotonic();io=process.io_counters();cpu=process.cpu_times()
    done=threading.Event();peak=dict(private_bytes=0,rss_bytes=0)
    def sample():
        while True:
            memory=process.memory_info()
            peak['private_bytes']=max(peak['private_bytes'],getattr(memory,'private',memory.vms))
            peak['rss_bytes']=max(peak['rss_bytes'],memory.rss)
            if done.wait(.1):break
    thread=threading.Thread(target=sample,daemon=True);thread.start()
    try:yield
    finally:
        done.set();thread.join();after=process.io_counters();after_cpu=process.cpu_times()
        result.update(elapsed_seconds=time.monotonic()-start,peak=peak,memory_sample_seconds=.1,
            cpu_seconds=after_cpu.user+after_cpu.system-cpu.user-cpu.system,
            process_logical_read_bytes=after.read_bytes-io.read_bytes,
            process_logical_write_bytes=after.write_bytes-io.write_bytes,
            physical_disk_bytes=None,includes_measurement_overhead=True)


def analyze(archive,*,page_size=50,progress=None):
    """All identifying values remain RAM-only; only aggregates escape this call."""
    if not 1<=page_size<=1000:raise ValueError('invalid bounded viewer page size')
    db=archive._db;phases={}
    def phase(name,operation):
        metrics={}
        if progress:progress(name,'running',metrics)
        try:
            with _measurement(metrics):value=operation()
        except Exception:
            if progress:progress(name,'failed',metrics)
            raise
        finally:phases[name]=metrics
        if progress:progress(name,'completed',metrics)
        return value
    base=''' FROM logical_record l JOIN observation_record o
        ON o.observation_id=l.representative_observation_id'''
    scoped_base=''' FROM observation_record o
        CROSS JOIN message_link ml ON ml.observation_id=o.observation_id
        CROSS JOIN logical_record l ON l.logical_id=ml.logical_id
        AND l.representative_observation_id=o.observation_id'''
    selected=phase('select_longest',lambda:db.execute('''SELECT o.account_alias,o.conversation_id,count(*)'''+base+'''
        GROUP BY o.account_alias,o.conversation_id ORDER BY count(*) DESC,o.account_alias,o.conversation_id LIMIT 1''').fetchone())
    _require(selected is not None)
    account,conversation,total=selected
    condition='o.account_alias IS ? AND o.conversation_id IS ?';parameters=[account,conversation]
    scope=dict(account_alias=account,conversation_id=conversation,null_account=account is None,null_conversation=conversation is None)
    order=" ORDER BY (o.event_time IS NULL),o.event_time,l.representative_observation_id,l.logical_id"
    def expected(extra='',values=(),offset=0):
        suffix=condition+(' AND '+extra if extra else '')
        count=db.execute('SELECT count(*)'+scoped_base+' WHERE '+suffix,[*parameters,*values]).fetchone()[0]
        ids=[r[0] for r in db.execute('SELECT l.logical_id'+scoped_base+' WHERE '+suffix+order+' LIMIT ? OFFSET ?',
            [*parameters,*values,page_size,offset])]
        return count,ids
    def checked_page(offset=0,*,extra='',values=(),filters=None,phase_name='page'):
        count,ids=phase(phase_name+'_reference',lambda:expected(extra,values,offset))
        result=phase(phase_name+'_api',lambda:viewer.messages(archive,limit=page_size,offset=offset,**scope,**(filters or {})))
        rows=result['rows']
        _require([r['logical_id'] for r in rows]==ids)
        _require(len(rows)==min(page_size,max(0,count-offset)))
        _require(all(r['account_alias']==account and r['conversation_id']==conversation for r in rows))
        keys=[(r['event_time'] is None,r['event_time'] or '',r['representative_observation_id'],r['logical_id']) for r in rows]
        _require(keys==sorted(keys))
        return rows,count
    pages={};counts={};private_rows=[]
    for name,offset in (('first',0),('middle',max(0,total//2-page_size//2)),('last',max(0,total-page_size))):
        rows,count=phase('page_'+name,lambda offset=offset,name=name:checked_page(offset,phase_name='page_'+name))
        pages[name]=dict(offset=offset,returned=len(rows),independent_total=count);private_rows.extend(rows)
    anchor=private_rows[len(private_rows)//2]
    for name,column in (('sender','sender_id'),('type','message_type')):
        chosen=db.execute('SELECT o.'+column+scoped_base+' WHERE '+condition+' AND o.'+column+' IS NOT NULL GROUP BY o.'+
            column+' ORDER BY count(*) DESC,o.'+column+' LIMIT 1',parameters).fetchone()
        if chosen is None:
            counts[name]=dict(exercised=False,reason='no_retained_nonnull_values');continue
        value=chosen[0]
        rows,count=phase('filter_'+name,lambda column=column,value=value,name=name:checked_page(extra='o.'+column+'=?',values=[str(value)],filters={column:value},phase_name='filter_'+name))
        _require(all(str(row[column])==str(value) for row in rows))
        counts[name]=dict(exercised=True,independent_total=count,returned=len(rows))
    dated=next((r for r in private_rows if r['event_time'] is not None),None)
    if dated is None:counts['date']=dict(exercised=False,reason='no_retained_known_times')
    else:
        since=datetime.fromisoformat(dated['event_time'].replace('Z','+00:00'))
        until=since+timedelta(days=1);since=since.isoformat();until=until.isoformat()
        rows,count=phase('filter_date',lambda:checked_page(extra='o.event_time>=? AND o.event_time<?',values=[since,until],filters=dict(since=since,until=until),phase_name='filter_date'))
        _require(all(since<=r['event_time']<until for r in rows))
        counts['date']=dict(exercised=True,independent_total=count,returned=len(rows),inclusive_start=True,exclusive_end=True)
    def context_probe():
        before=min(20,page_size//2)
        result=phase('context_api',lambda:viewer.context(archive,anchor['logical_id'],before=before,limit=page_size))
        position=db.execute('SELECT count(*)'+scoped_base+' WHERE '+condition+''' AND
            (o.event_time IS NULL,coalesce(o.event_time,''),l.representative_observation_id,l.logical_id)<(?,?,?,?)''',
            [*parameters,anchor['event_time'] is None,anchor['event_time'] or '',anchor['representative_observation_id'],anchor['logical_id']]).fetchone()[0]
        _require(result['anchor_position']==position and result['offset']==max(0,position-before))
        _,ids=expected(offset=result['offset'])
        _require([r['logical_id'] for r in result['rows']]==ids and anchor['logical_id'] in ids)
        _require(all(r['conversation_id']==conversation and r['account_alias']==account for r in result['rows']))
        return dict(returned=len(ids),anchor_position=position,offset=result['offset'],anchor_present=True)
    context=phase('context',context_probe)
    def detail_probe():
        result=viewer.detail(archive,anchor['logical_id'])
        observations=result['observations']
        expected_count=db.execute('SELECT count(*) FROM message_link WHERE logical_id=?',(anchor['logical_id'],)).fetchone()[0]
        conflicts=db.execute('SELECT count(*) FROM conflict WHERE logical_id=?',(anchor['logical_id'],)).fetchone()[0]
        _require(len(observations)==expected_count==result['message']['observation_count'])
        _require(len(result['conflicts'])==conflicts)
        _require(all(all(k in row for k in ('source_id','snapshot_id','row_hash','raw_record','native_locator','dedupe_evidence')) for row in observations))
        return dict(observations=len(observations),sources=len({o['source_id'] for o in observations}),
            snapshots=len({o['snapshot_id'] for o in observations}),distinct_raw_row_hashes=len({o['row_hash'] for o in observations}),
            conflict_fields=len(result['conflicts']),candidates_returned=len(result['candidates']),
            candidates_are_confirmed_duplicates=result['candidates_are_confirmed_duplicates'],representative_is_latest=result['representative_is_latest'])
    detail=phase('detail',detail_probe)
    def conversations_probe():
        result=phase('conversations_api',lambda:viewer.conversations(archive,limit=page_size))
        expected_rows=phase('conversations_reference',lambda:list(db.execute('''SELECT o.account_alias,o.conversation_id,
            count(*),min(o.event_time),max(o.event_time),sum(l.conflict_count>0)'''+base+'''
            GROUP BY o.account_alias,o.conversation_id ORDER BY max(o.event_time) DESC,
            o.account_alias,o.conversation_id LIMIT ?''',(page_size,))))
        fields=('account_alias','conversation_id','message_count','first_time','last_time','messages_with_conflict')
        _require([tuple(row.get(k) for k in fields) for row in result['rows']]==[tuple(row) for row in expected_rows])
        return dict(returned=len(expected_rows),independent_aggregate_fields_verified=True)
    conversations=phase('conversations',conversations_probe)
    def names_probe():
        identities={(account,conversation),(anchor.get('account_alias'),anchor.get('sender_id'))}
        results=[viewer.names(archive,*identity) for identity in identities]
        return dict(identities_sampled=len(identities),identities_with_observed_name=sum(bool(rows) for rows in results),
            observed_name_rows=sum(len(rows) for rows in results))
    names=phase('names_api',names_probe)
    def name_coverage():
        present=db.execute("SELECT 1 FROM sqlite_master WHERE name='next_viewer_identity'").fetchone() is not None
        result={}
        for name,column in (('conversations','conversation_id'),('senders','sender_id')):
            target='(SELECT DISTINCT o.account_alias,o.'+column+' identifier'+base+') p'
            hit="EXISTS(SELECT 1 FROM next_viewer_identity i WHERE i.account_alias IS p.account_alias AND i.username IS p.identifier AND trim(i.name)<>'' AND i.name<>i.username)" if present else '0'
            pairs,known,hits=db.execute('SELECT count(*),sum(p.identifier IS NOT NULL),sum('+hit+') FROM '+target).fetchone()
            result[name]=dict(unique_account_identity_pairs=pairs,nonnull_identity_pairs=known or 0,
                observed_readable_name_hits=hits or 0,hit_rate_among_nonnull=(hits or 0)/known if known else None)
        return dict(result,definition='distinct_account_identity_pairs_with_nonempty_observed_name_different_from_identifier',historical_names_not_message_time_identity=True)
    coverage=phase('name_coverage',name_coverage)
    return dict(pass_all=True,longest_conversation_messages=total,page_size=page_size,pages=pages,filters=counts,
        context=context,detail=detail,conversations=conversations,names=names,name_coverage=coverage,phases=phases,
        source_version_provenance_preserved=True,conversation_boundaries_verified=True,stable_time_order_verified=True)


def explain(archive,*,page_size=50):
    """Explain actual viewer SELECT without executing/decompressing its rows."""
    db=archive._db
    selected=db.execute('''SELECT o.account_alias,o.conversation_id,count(*) FROM logical_record l
        JOIN observation_record o ON o.observation_id=l.representative_observation_id
        GROUP BY o.account_alias,o.conversation_id ORDER BY count(*) DESC,o.account_alias,o.conversation_id LIMIT 1''').fetchone()
    _require(selected is not None)
    account,conversation,total=selected;plans={}
    class ExplainOnly:
        def execute(self,query,parameters=()):
            if query.lstrip().upper().startswith('SELECT') and 'sqlite_master' not in query:
                plans['actual_viewer_page']=[r[3] for r in db.execute('EXPLAIN QUERY PLAN '+query,parameters)]
                return []
            if 'sqlite_master' in query:return db.execute(query,parameters)
            if query.startswith('PRAGMA index_info('):return db.execute(query,parameters)
            raise ValueError('explain-only unexpected statement refused')
    archive._db=ExplainOnly()
    try:viewer.messages(archive,limit=page_size,account_alias=account,conversation_id=conversation,
        null_account=account is None,null_conversation=conversation is None)
    finally:archive._db=db
    _require('actual_viewer_page' in plans)
    candidate='''WITH page AS MATERIALIZED (
        SELECT l.logical_id,l.representative_observation_id,o.event_time FROM observation_record o
        CROSS JOIN message_link ml ON ml.observation_id=o.observation_id
        CROSS JOIN logical_record l ON l.logical_id=ml.logical_id AND l.representative_observation_id=o.observation_id
        WHERE o.account_alias IS ? AND o.conversation_id IS ?
        ORDER BY (o.event_time IS NULL),o.event_time,l.representative_observation_id,l.logical_id LIMIT ? OFFSET ?)
        SELECT m.* FROM page CROSS JOIN logical_message m ON m.logical_id=page.logical_id
        ORDER BY (page.event_time IS NULL),page.event_time,page.representative_observation_id,page.logical_id'''
    plans['candidate_keys_first_existing_indexes']=[r[3] for r in db.execute('EXPLAIN QUERY PLAN '+candidate,(account,conversation,page_size,0))]
    return dict(pass_all=True,scope='query_plan_only_candidate_not_execution_or_correctness_proof',
        longest_conversation_messages=total,plans=plans,query_parameters_exported=False,
        candidate_requires_schema_change=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('state','union','out'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--page-size',type=int,default=50)
    parser.add_argument('--cache-kib',type=int,default=2000,help='readonly page-cache budget; default matches normal UI connections')
    parser.add_argument('--explain-only',action='store_true');args=parser.parse_args(argv)
    if not 1<=args.page_size<=1000 or not 16<=args.cache_kib<=HEAVY_CACHE_KIB:
        parser.error('bounded page size and cache budget required')
    args.state=local_absolute(args.state,allow_relative=True);args.union=local_absolute(args.union,allow_relative=True)
    args.out=local_absolute(args.out,allow_relative=True)
    workspace=Path(__file__).resolve().parents[1]
    if not args.out.is_relative_to(workspace/'working') or not args.out.name.endswith('.private.json'):
        raise ValueError('aggregate receipt must be a private file under working')
    if args.out.exists():raise FileExistsError('fresh private aggregate receipt required')
    phase_path=args.out.with_name(args.out.stem+'.phases.private.json')
    if phase_path.exists():raise FileExistsError('fresh private phase receipt required')
    if any(args.out.is_relative_to(p) or p.is_relative_to(args.out.parent) for p in (args.state,args.union)):
        raise ValueError('receipt must not overlap protected inputs')
    args.out.parent.mkdir(parents=True,exist_ok=True)
    result=dict(schema='next-viewer-aggregate-acceptance-1',phone_completeness=False,capture_started=False,
        readonly=True,immutable=True,lifetime_cold_guards=True,identifiers_or_contents_exported=False,
        process_io_scope='logical_not_physical_disk',readonly_cache_budget_kib=args.cache_kib,
        process_measurement_includes_progress_receipt_writes=True,pass_all=False)
    result['source_provenance_before']=_source_provenance()
    metrics={}
    phases={}
    process=psutil.Process()
    def progress(name,status,measurement):
        if status=='running':
            io=process.io_counters();cpu=process.cpu_times()
            phases[name]=dict(status=status,started_unix=time.time(),cpu_seconds_at_start=cpu.user+cpu.system,
                process_logical_read_bytes_at_start=io.read_bytes,process_logical_write_bytes_at_start=io.write_bytes,
                measurement=dict(measurement))
        else:phases[name].update(status=status,measurement=dict(measurement))
        atomic_json(phase_path,dict(schema='next-viewer-aggregate-phases-1',phases=phases,
            current_phase=dict(name=name,status=status,started_unix=phases[name]['started_unix'])))
    try:
        with _measurement(metrics),writer_lock(args.state),writer_lock(args.union),_offline(args.state) as service:
            path,_=_formal(args.union,_instance(service))
            with cold_input(path),CompactArchive(path,readonly=True,immutable=True) as archive:
                archive._db.execute(f'PRAGMA cache_size=-{args.cache_kib}')
                archive._db.execute('BEGIN')
                from .viewer_access import present
                result['representative_cover_index_present']=present(archive)
                result.update(explain(archive,page_size=args.page_size) if args.explain_only else
                    analyze(archive,page_size=args.page_size,progress=progress))
    except Exception as error:
        result.update(pass_all=False,error_type=type(error).__name__)
    result['source_provenance_after']=_source_provenance()
    result['measured_source_or_revision_changed']=result['source_provenance_before']!=result['source_provenance_after']
    if result['measured_source_or_revision_changed']:result['pass_all']=False
    result['measurement']=metrics;write_json_new(args.out,result)
    print(json.dumps(dict(pass_all=result['pass_all'],elapsed_seconds=metrics.get('elapsed_seconds'),error_type=result.get('error_type'))),flush=True)
    return int(not result['pass_all'])


if __name__=='__main__':raise SystemExit(main())
