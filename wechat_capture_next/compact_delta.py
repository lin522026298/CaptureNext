"""Indexed, append-only derivation for the next-only compact archive.

This is not a replacement for an explicit full rebuild/repair.  It assumes a
correct derived baseline and immutable observations under the same rule.  A new
observation cannot change an existing observation's logical identity.  Thus only
its group and observation-pairs with at least one new endpoint can change.

The archive owns the transaction, raw storage and body-pool search index.  This
module never commits and never reads original-record payloads.
"""
from collections import defaultdict
import hashlib
import json
import unicodedata

from wua.store import RULE_VERSION, _hash, _json, _known, _stable_conversation, _strong_key, _time_us


TABLES = ('logical_message', 'message_link', 'conflict', 'dedupe_candidate')
PROJECTION = '''o.observation_id,o.snapshot_id,o.account_alias,o.conversation_id,
    o.sender_id,o.direction,o.event_time,o.message_type,o.server_id,o.body_text,
    s.source_id'''


def ensure_delta_schema(archive):
    """Create auxiliary indexes; only call inside the archive's transaction."""
    db = archive._db
    if not db.in_transaction:
        raise ValueError('merge schema requires the archive transaction')
    existing = db.execute("SELECT 1 FROM sqlite_master WHERE name='next_merge_projection'").fetchone()
    if not existing and db.execute('SELECT 1 FROM message_observation LIMIT 1').fetchone():
        raise ValueError('nonempty archive requires an explicit merge-index bootstrap')
    db.execute('''CREATE TABLE IF NOT EXISTS next_merge_projection(
        observation_id TEXT PRIMARY KEY, logical_id TEXT NOT NULL,
        anchor_json TEXT, stable_conversation INTEGER NOT NULL,
        candidate_account TEXT, candidate_body_hash TEXT, time_us INTEGER)''')
    db.execute('''CREATE INDEX IF NOT EXISTS next_merge_group
        ON next_merge_projection(logical_id,observation_id)''')
    db.execute('''CREATE INDEX IF NOT EXISTS next_merge_neighbor
        ON next_merge_projection(candidate_account,candidate_body_hash,time_us,observation_id)''')
    db.execute('''CREATE INDEX IF NOT EXISTS next_merge_bucket_group
        ON next_merge_projection(candidate_account,candidate_body_hash,logical_id,time_us,observation_id)''')


def _body(row):
    return ' '.join(unicodedata.normalize('NFC', row['body_text']).split()) if row['body_text'] else ''


def _body_hash(body):
    return hashlib.sha256(body.encode('utf-8')).hexdigest()


def register_observation(archive, prepared):
    """Index one actually inserted prepared observation in its import transaction."""
    if not archive._db.in_transaction:
        raise ValueError('observation registration requires the archive transaction')
    anchor = _strong_key(prepared)
    logical_id = 'msg_' + _hash([RULE_VERSION, 'strong', anchor] if anchor else
                              [RULE_VERSION, 'single', prepared['observation_id']])
    stable = _stable_conversation(json.loads(prepared['normalized_json']))
    timestamp = _time_us(prepared['event_time'])
    body = _body(prepared)
    eligible = _known(prepared['account_alias']) and bool(body) and timestamp is not None
    archive._db.execute('INSERT INTO next_merge_projection VALUES(?,?,?,?,?,?,?)',
        (prepared['observation_id'], logical_id, _json(anchor) if anchor else None,
         int(stable), prepared['account_alias'] if eligible else None,
         _body_hash(body) if eligible else None,
         timestamp if eligible else None))
    return logical_id


def _rows(archive, where, parameters):
    # CROSS JOIN preserves the indexed projection as the outer lookup, rather
    # than letting a view expansion choose a scan of the observation corpus.
    query = f'''SELECT {PROJECTION},p.logical_id AS _logical_id,
        p.anchor_json AS _anchor_json,p.stable_conversation AS _stable
        FROM next_merge_projection p CROSS JOIN message_observation o
        ON o.observation_id=p.observation_id
        JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id
        WHERE {where} ORDER BY o.observation_id'''
    return archive._db.execute(query, parameters)


def _group_state(logical_id, members):
    representative = members[0]
    conflicts = []
    for field in ('body_text', 'event_time'):
        values = defaultdict(list)
        for row in members:
            values[_json(row[field])].append(row['observation_id'])
        if len(values) > 1:
            evidence = [{'value': json.loads(value), 'observation_ids': ids}
                        for value, ids in sorted(values.items())]
            conflicts.append((logical_id, field, _json(evidence), RULE_VERSION))
    values = [representative[key] for key in ('account_alias', 'conversation_id',
        'sender_id', 'direction', 'event_time', 'message_type', 'server_id', 'body_text')]
    parent = tuple([logical_id, representative['observation_id'], *values, len(members),
        len({r['source_id'] for r in members}), len({r['snapshot_id'] for r in members}),
        len(conflicts), RULE_VERSION])
    links = []
    for row in members:
        anchor = json.loads(row['_anchor_json']) if row['_anchor_json'] else None
        evidence = {'representative_rule': 'lexicographic_min_observation_id',
                    'representative_observation_id': representative['observation_id']}
        if anchor:
            evidence['strong_anchor'] = dict(zip(('account_alias', 'conversation_id',
                'sender_id', 'direction', 'message_type', 'server_id'), anchor))
        links.append((row['observation_id'], logical_id, RULE_VERSION,
            'strong_server_identity' if anchor else 'unmerged_observation',
            'strong' if anchor else 'none', _json(evidence)))
    return {'logical_message': [parent], 'message_link': links, 'conflict': conflicts}


def _compare(old, wanted, keys):
    previous = {tuple(row[:keys]): tuple(row) for row in old}
    desired = {tuple(row[:keys]): tuple(row) for row in wanted}
    return dict(insert=[desired[key] for key in sorted(desired.keys()-previous.keys())],
                update=[desired[key] for key in sorted(desired.keys() & previous.keys())
                        if desired[key] != previous[key]],
                delete=[key for key in sorted(previous.keys()-desired.keys())])


def _candidate(left, right):
    if left['_logical_id'] == right['_logical_id']:
        return None
    if left['server_id'] and right['server_id'] and left['server_id'] != right['server_id']:
        return None
    if left['_stable'] and right['_stable'] and left['conversation_id'] != right['conversation_id']:
        return None
    # The indexed hash is an accelerator only. Preserve exact bucket equality
    # even if hashes collide or an alternative hasher is used in a test.
    if left['account_alias'] != right['account_alias'] or _body(left) != _body(right):
        return None
    medium = left['_stable'] and right['_stable'] and all(
        _known(left[key]) and left[key] == right[key]
        for key in ('conversation_id', 'sender_id', 'direction', 'message_type'))
    confidence = 'medium' if medium else 'weak'
    pair = sorted((left['_logical_id'], right['_logical_id']))
    candidate_id = 'candidate_' + _hash([RULE_VERSION, pair, confidence])
    evidence = _json({'observation_ids': sorted((left['observation_id'], right['observation_id'])),
        'time_delta_microseconds': abs(_time_us(left['event_time'])-_time_us(right['event_time'])),
        'normalization': 'NFC-and-collapsed-whitespace', 'automatic_merge': False})
    return (candidate_id, *pair, confidence, 'same_normalized_body_narrow_time', evidence, RULE_VERSION)


def rebuild_delta(archive, new_ids):
    """Derive exactly the append delta. ``new_ids`` must be actual new inserts.

    An iterable is consumed into a temporary SQLite table, not a corpus-sized
    Python set. Auxiliary state and every derived write share the caller's
    transaction and are rolled back together on any failure.
    """
    db = archive._db
    if not db.in_transaction:
        raise ValueError('delta rebuild requires the archive transaction')
    db.execute('CREATE TEMP TABLE IF NOT EXISTS next_delta_new(observation_id TEXT PRIMARY KEY)')
    db.execute('DELETE FROM next_delta_new')
    db.executemany('INSERT OR IGNORE INTO next_delta_new VALUES(?)', ((item,) for item in new_ids))
    missing = db.execute('''SELECT 1 FROM next_delta_new n LEFT JOIN next_merge_projection p
        ON p.observation_id=n.observation_id WHERE p.observation_id IS NULL LIMIT 1''').fetchone()
    if missing:
        raise ValueError('new observation missing merge projection')
    deltas = {table: dict(insert=[], update=[], delete=[]) for table in TABLES}
    group_ids = db.execute('''SELECT DISTINCT p.logical_id FROM next_delta_new n
        JOIN next_merge_projection p ON p.observation_id=n.observation_id ORDER BY p.logical_id''')
    groups_read = observations_read = neighbor_pairs = 0
    for (logical_id,) in group_ids:
        members = [dict(row) for row in _rows(archive, 'p.logical_id=?', (logical_id,))]
        groups_read += 1
        observations_read += len(members)
        desired = _group_state(logical_id, members)
        for table in ('logical_message', 'message_link', 'conflict'):
            old = db.execute(f'SELECT * FROM {table} WHERE logical_id=?', (logical_id,)).fetchall()
            delta = _compare(old, desired[table], 2 if table == 'conflict' else 1)
            for action in delta:
                deltas[table][action].extend(delta[action])
    candidates = {}
    other_group_exists = {}
    new_rows = db.execute('''SELECT p.observation_id,p.candidate_account,p.candidate_body_hash,p.time_us
        ,p.logical_id
        FROM next_delta_new n JOIN next_merge_projection p ON p.observation_id=n.observation_id
        WHERE p.candidate_account IS NOT NULL ORDER BY p.observation_id''')
    for obs_id, account, body_hash, timestamp, logical_id in new_rows:
        bucket_group = (account, body_hash, logical_id)
        if bucket_group not in other_group_exists:
            # A time-window index alone would still visit N same-group index
            # entries for each of N new observations, even with a SQL != filter.
            # Two indexed logical-ID ranges prove a singleton bucket in O(log N)
            # once per batch/bucket/group, before any body is decoded.
            other_group_exists[bucket_group] = any(db.execute('''SELECT 1
                FROM next_merge_projection INDEXED BY next_merge_bucket_group
                WHERE candidate_account=? AND candidate_body_hash=? AND logical_id '''+operator+''' ?
                LIMIT 1''', (account, body_hash, logical_id)).fetchone() is not None
                for operator in ('<', '>'))
        if not other_group_exists[bucket_group]:
            continue
        left = dict(next(iter(_rows(archive, 'p.observation_id=?', (obs_id,)))))
        for neighbor in _rows(archive, '''p.candidate_account=? AND p.candidate_body_hash=?
                AND p.time_us BETWEEN ? AND ? AND p.logical_id<>?
                AND (p.observation_id>? OR NOT EXISTS(SELECT 1 FROM next_delta_new nn
                    WHERE nn.observation_id=p.observation_id))''',
                (account, body_hash, timestamp-2_000_000, timestamp+2_000_000, logical_id, obs_id)):
            neighbor_pairs += 1
            candidate = _candidate(left, dict(neighbor))
            if candidate and (candidate[0] not in candidates or candidate < candidates[candidate[0]]):
                candidates[candidate[0]] = candidate
    for candidate_id, candidate in sorted(candidates.items()):
        old = db.execute('SELECT * FROM dedupe_candidate WHERE candidate_id=?', (candidate_id,)).fetchone()
        if old is None:
            deltas['dedupe_candidate']['insert'].append(candidate)
        elif candidate < tuple(old):
            deltas['dedupe_candidate']['update'].append(candidate)
    changed = any(any(delta.values()) for delta in deltas.values())
    if changed:
        archive._apply_rows('logical_message', deltas['logical_message'])
        for table in ('dedupe_candidate', 'conflict', 'message_link'):
            archive._apply_rows(table, deltas[table], delete=True)
        for table in ('message_link', 'conflict', 'dedupe_candidate'):
            archive._apply_rows(table, deltas[table])
        archive._apply_rows('logical_message', deltas['logical_message'], delete=True)
    archive.last_rebuild_writes = {table: {action: len(rows) for action, rows in delta.items()}
                                   for table, delta in deltas.items()}
    archive.last_rebuild_reads = dict(dirty_groups=groups_read,
        group_observations=observations_read, neighbor_pairs=neighbor_pairs)
    return dict(rebuild_changed=changed,
        added_logical_messages=len(deltas['logical_message']['insert']), totals=archive.stats())
