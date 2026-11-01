"""Read-only conversation, context and provenance APIs for compact archives.

Display names are observations, never identity/merge keys. No live-client or
key access belongs in this module. All untrusted strings are returned as data.
"""
import json
import re


def _representatives(archive,observation='o',logical='l'):
    from .viewer_access import present,INDEX
    if present(archive):
        return ('FROM observation_record '+observation+' CROSS JOIN logical_record '+logical+
            ' INDEXED BY '+INDEX+' ON '+logical+'.representative_observation_id='+observation+'.observation_id ')
    return ('FROM observation_record '+observation+' JOIN message_link vlink ON vlink.observation_id='+observation+'.observation_id '
        'JOIN logical_record '+logical+' ON '+logical+'.logical_id=vlink.logical_id AND '+
        logical+'.representative_observation_id='+observation+'.observation_id ')


def _present(archive,table):
    return archive._db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is not None


def names(archive,account,username):
    if not _present(archive,'next_viewer_identity'):return []
    rows=archive._db.execute('''SELECT DISTINCT i.source_id,i.name,i.kind,i.snapshot_id
        FROM next_viewer_identity i WHERE i.account_alias=? AND i.username=?
        ORDER BY i.snapshot_id DESC,i.kind,i.name''',(account,username))
    return [dict(r) for r in rows]


def label(archive,account,username):
    rows=names(archive,account,username)
    if not rows:return username or '身份未知'
    # Do not choose one historical or cross-device name as the authoritative
    # identity. Multiple observed display values remain visible and inspectable.
    priority={'remark':0,'nick_name':1,'alias':2,'session_title':3}
    selected=sorted(rows,key=lambda r:(priority.get(r['kind'],9),r['name']))
    values=list(dict.fromkeys(r['name'] for r in selected))
    return ' / '.join(values[:3])+('（另有名称）' if len(values)>3 else '')


def decorate(archive,rows):
    cache={}
    for row in rows:
        for kind,column in (('conversation_name','conversation_id'),('sender_name','sender_id')):
            key=(row.get('account_alias'),row.get(column))
            if key not in cache:cache[key]=label(archive,*key)
            row[kind]=cache[key]
    return rows


def conversations(archive,*,limit=50,offset=0,search=''):
    parameters=[];where=''
    if search:
        literal='%'+search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
        where="WHERE o.conversation_id LIKE ? ESCAPE '\\'"
        parameters.append(literal)
        if _present(archive,'next_viewer_identity'):
            where+=''' OR EXISTS(SELECT 1 FROM next_viewer_identity i WHERE i.account_alias=o.account_alias
                AND i.username=o.conversation_id AND i.name LIKE ? ESCAPE '\\')'''
            parameters.append(literal)
    rows=[dict(r) for r in archive._db.execute('''SELECT o.account_alias,o.conversation_id,
        count(*) message_count,min(o.event_time) first_time,max(o.event_time) last_time,
        sum(l.conflict_count>0) messages_with_conflict '''+_representatives(archive)+where+'''
        GROUP BY o.account_alias,o.conversation_id ORDER BY max(o.event_time) DESC,
        o.account_alias,o.conversation_id LIMIT ? OFFSET ?''',[*parameters,limit,offset])]
    return dict(rows=decorate(archive,rows),next_offset=offset+len(rows) if len(rows)==limit else None,
        naming_scope='observed_auxiliary_names_not_names_at_message_time')


def messages(archive,*,limit=50,offset=0,null_account=False,null_conversation=False,**filters):
    original=archive._db
    nulls=['m.'+name+' IS NULL' for name,enabled in (('account_alias',null_account),('conversation_id',null_conversation)) if enabled]
    class Filtered:
        def execute(self,query,parameters=()):
            if query.startswith('SELECT m.* FROM logical_message m'):
                # Validate/build filters through the established list API, but
                # select only lightweight page keys BEFORE expanding text and
                # recipe joins. OFFSET must not decode every preceding body.
                if nulls:
                    head,order=query.split(' ORDER BY ',1)
                    head+=(' AND ' if ' WHERE ' in head else ' WHERE ')+' AND '.join(nulls)
                    query=head+' ORDER BY '+order
                stored={'logical_id','representative_observation_id','observation_count','source_count',
                    'snapshot_count','conflict_count','rule_version'}
                keys=query.replace('SELECT m.* FROM logical_message m','SELECT vl.logical_id '+
                    _representatives(archive,'vo','vl'),1)
                keys=re.sub(r'\bm\.([a-z_]+)',lambda match:('vl.' if match[1] in stored else 'vo.')+match[1],keys)
                keys=keys.replace('JOIN message_observation o ON','JOIN observation_record o ON')
                keys=keys.replace('JOIN message_observation so ON','JOIN observation_record so ON')
                keys=keys.replace('so.body_text LIKE',
                    '(SELECT body_text FROM body_content WHERE id=so.body_text) LIKE')
                ids=[row[0] for row in original.execute(keys,parameters)];expanded={}
                for start in range(0,len(ids),200):
                    part=ids[start:start+200]
                    for row in original.execute('SELECT * FROM logical_message WHERE logical_id IN ('+
                            ','.join('?' for _ in part)+')',part):expanded[row['logical_id']]=row
                return [expanded[ident] for ident in ids]
            return original.execute(query,parameters)
    try:
        archive._db=Filtered()
        rows=archive.list_messages(limit=limit,offset=offset,**filters)
    finally:archive._db=original
    rows=decorate(archive,rows)
    return dict(rows=rows,next_offset=offset+len(rows) if len(rows)==limit else None,
        scope='unified_logical_messages_all_retained_observations_searchable')


def context(archive,logical_id,*,before=20,limit=50):
    row=archive._db.execute('SELECT * FROM logical_message WHERE logical_id=?',(logical_id,)).fetchone()
    if row is None:raise KeyError('message not found')
    key=(row['event_time'] is None,row['event_time'] or '',row['representative_observation_id'],logical_id)
    position=archive._db.execute('SELECT count(*) '+_representatives(archive)+'''WHERE o.account_alias IS ? AND o.conversation_id IS ?
        AND (o.event_time IS NULL,coalesce(o.event_time,''),l.representative_observation_id,l.logical_id)<(?,?,?,?)''',
        (row['account_alias'],row['conversation_id'],*key)).fetchone()[0]
    offset=max(0,position-before)
    result=messages(archive,account_alias=row['account_alias'],conversation_id=row['conversation_id'],limit=limit,offset=offset,
        null_account=row['account_alias'] is None,null_conversation=row['conversation_id'] is None)
    result.update(anchor=logical_id,anchor_position=position,offset=offset,
        account_alias=row['account_alias'],conversation_id=row['conversation_id'])
    return result


def detail(archive,logical_id,*,candidate_offset=0):
    row=archive._db.execute('SELECT * FROM logical_message WHERE logical_id=?',(logical_id,)).fetchone()
    if row is None:raise KeyError('message not found')
    representative=dict(row);observations=archive.get_observations(logical_id)
    fields=('body_text','sender_id','event_time','message_type','server_id','conversation_id')
    for item in observations:
        item['differences_from_representative']={k:dict(representative=representative.get(k),observed=item.get(k))
            for k in fields if representative.get(k)!=item.get(k)}
        # The expanded exact values below already preserve these JSON strings;
        # avoid sending two copies of long text over HTTP, not dropping fields.
        for key in ('raw_record_json','native_locator_json','raw_time_json','normalized_json',
                    'snapshot_metadata_json','source_metadata_json','evidence_json'):item.pop(key,None)
    candidates=[]
    for candidate in archive._db.execute('''SELECT * FROM dedupe_candidate WHERE left_logical_id=? OR right_logical_id=?
        ORDER BY candidate_id LIMIT 100 OFFSET ?''',(logical_id,logical_id,candidate_offset)):
        item=dict(candidate);item['evidence']=json.loads(item.pop('evidence_json'));candidates.append(item)
    from .viewer_media import for_message
    return dict(message=decorate(archive,[representative])[0],observations=observations,media=for_message(archive,logical_id),
        conflicts=archive.get_conflicts(logical_id),candidates=candidates,
        candidate_next_offset=candidate_offset+len(candidates) if len(candidates)==100 else None,
        candidates_are_confirmed_duplicates=False,representative_is_latest=False,
        identities={k:names(archive,row['account_alias'],row[k]) for k in ('conversation_id','sender_id')})
