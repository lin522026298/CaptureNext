"""Column-projection-only WUA memory optimization; same rules/search/schema.

The reducer is intentionally kept equivalent to the frozen baseline. It does
not redesign candidates or FTS. Unused original records remain on disk in the
archive, not in every Python observation dictionary during a full rebuild.
"""
from collections import defaultdict
import json

from wua.store import ArchiveStore, RULE_VERSION, _DERIVED_TABLES, _hash, _json, _strong_key


class LeanArchiveStore(ArchiveStore):
    def __init__(self, path, *, readonly=False, temp_store='memory'):
        if temp_store not in ('memory', 'file', 'default'):
            raise ValueError('unsupported connection-local temporary storage')
        super().__init__(path, readonly=readonly)
        if temp_store != 'default':
            self._db.execute('PRAGMA temp_store='+temp_store.upper())
        self.last_rebuild_writes = {}

    def _delta(self, table, desired, key_columns=1, fts=False):
        cursor = self._db.execute(('SELECT logical_id,body_text,rowid FROM message_fts ORDER BY logical_id'
                                  if fts else f'SELECT * FROM {table} ORDER BY 1,2'))
        delta = dict(insert=[], update=[], delete=[])
        try:
            wanted = iter(desired)
            old, new = next(cursor, None), next(wanted, None)
            previous_key = None
            while old is not None or new is not None:
                old_key = tuple(old[:key_columns]) if old is not None else None
                new_key = new[:key_columns] if new is not None else None
                if old_key is not None and previous_key is not None and old_key <= previous_key:
                    raise ValueError('duplicate/unsorted derived key; refusing ambiguous update')
                if old is None or (new is not None and new_key < old_key):
                    delta['insert'].append(new)
                    new = next(wanted, None)
                elif new is None or old_key < new_key:
                    delta['delete'].append((old[-1],) if fts else old_key)
                    previous_key = old_key
                    old = next(cursor, None)
                else:
                    old_values = tuple(old[:2]) if fts else tuple(old)
                    if old_values != new:
                        delta['update'].append((new[1], old[-1]) if fts else new)
                    previous_key = old_key
                    old, new = next(cursor, None), next(wanted, None)
            return delta
        finally:
            cursor.close()

    def _apply_rows(self, table, delta, *, delete=False):
        columns = [r[1] for r in self._db.execute(f'PRAGMA table_info({table})')]
        keys = 2 if table == 'conflict' else 1
        where = ' AND '.join(f'{name}=?' for name in columns[:keys])
        if delete:
            self._db.executemany(f'DELETE FROM {table} WHERE {where}', delta['delete'])
            return
        self._db.executemany(f'INSERT INTO {table} VALUES ('+','.join('?' for _ in columns)+')', delta['insert'])
        self._db.executemany(f'UPDATE {table} SET '+','.join(f'{c}=?' for c in columns[keys:])+f' WHERE {where}',
                            (row[keys:]+row[:keys] for row in delta['update']))

    def _rebuild(self):
        desired = self._desired_state()
        deltas = {name: self._delta(name, desired[name], 2 if name == 'conflict' else 1)
                  for name in _DERIVED_TABLES}
        changed = any(any(delta.values()) for delta in deltas.values())
        added = len(deltas['logical_message']['insert'])
        fts_rows, fts_changed = [], False
        if self.fts_enabled:
            mapping = {row[0]: row[1] for row in desired['message_link']}
            bodies = defaultdict(set)
            for observation, body in self._db.execute('SELECT observation_id,body_text FROM message_observation'):
                if body:
                    bodies[mapping[observation]].add(body)
            fts_rows = [(logical_id, '\n'.join(sorted(values))) for logical_id, values in sorted(bodies.items())]
            fts_delta = self._delta('message_fts', fts_rows, fts=True)
            fts_changed = any(fts_delta.values())
        # Compare completely and close every cursor BEFORE mutating tables.
        # Parents first, old children removed/re-homed, obsolete parents last.
        # No REPLACE, disabled FK, internal COMMIT, or whole-table DELETE.
        if changed:
            self._apply_rows('logical_message', deltas['logical_message'])
            for name in ('dedupe_candidate', 'conflict', 'message_link', 'logical_message'):
                if name != 'logical_message':
                    self._apply_rows(name, deltas[name], delete=True)
            for name in ('message_link', 'conflict', 'dedupe_candidate'):
                self._apply_rows(name, deltas[name])
            self._apply_rows('logical_message', deltas['logical_message'], delete=True)
        if fts_changed:
            self._db.executemany('DELETE FROM message_fts WHERE rowid=?', fts_delta['delete'])
            self._db.executemany('UPDATE message_fts SET body_text=? WHERE rowid=?', fts_delta['update'])
            self._db.executemany('INSERT INTO message_fts(logical_id,body_text) VALUES (?,?)', fts_delta['insert'])
        self.last_rebuild_writes = {name: {action: len(rows) for action, rows in delta.items()}
                                   for name, delta in deltas.items()}
        if self.fts_enabled:
            self.last_rebuild_writes['message_fts'] = {action: len(rows) for action, rows in fts_delta.items()}
        return {'rebuild_changed': changed or fts_changed, 'added_logical_messages': added, 'totals': self.stats()}

    def _merge_rows(self):
        for row in self._db.execute('''SELECT o.observation_id,o.snapshot_id,
            o.account_alias,o.conversation_id,o.sender_id,o.direction,o.event_time,
            o.message_type,o.server_id,o.body_text,o.normalized_json,s.source_id
            FROM message_observation o JOIN source_snapshot s ON o.snapshot_id=s.snapshot_id
            ORDER BY o.observation_id'''):
            item = dict(row)
            # These are the ONLY normalized-input keys read by the unchanged
            # _strong_key/_candidates helpers; preserve JSON types exactly.
            normalized = json.loads(item['normalized_json'])
            item['normalized_json'] = _json({key: normalized[key] for key in
                ('conversation_id', 'conversation_id_is_stable') if key in normalized})
            yield item

    def _desired_state(self):
        observations = list(self._merge_rows())
        groups = defaultdict(list)
        for row in observations:
            anchor = _strong_key(row)
            identity = [RULE_VERSION, 'strong', anchor] if anchor else [RULE_VERSION, 'single', row['observation_id']]
            logical_id = 'msg_' + _hash(identity)
            row['_anchor'], row['_logical_id'] = anchor, logical_id
            groups[logical_id].append(row)
        desired = {name: [] for name in _DERIVED_TABLES}
        for logical_id, members in sorted(groups.items()):
            representative = members[0]
            conflicts = []
            for field in ('body_text', 'event_time'):
                values = defaultdict(list)
                for member in members:
                    values[_json(member[field])].append(member['observation_id'])
                if len(values) > 1:
                    evidence = [{'value': json.loads(value), 'observation_ids': ids}
                                for value, ids in sorted(values.items())]
                    conflicts.append((logical_id, field, _json(evidence), RULE_VERSION))
            desired['conflict'].extend(conflicts)
            values = [representative[key] for key in ('account_alias', 'conversation_id', 'sender_id',
                'direction', 'event_time', 'message_type', 'server_id', 'body_text')]
            desired['logical_message'].append(tuple([logical_id, representative['observation_id'], *values,
                len(members), len({row['source_id'] for row in members}),
                len({row['snapshot_id'] for row in members}), len(conflicts), RULE_VERSION]))
            for member in members:
                anchor = member['_anchor']
                evidence = {'representative_rule': 'lexicographic_min_observation_id',
                            'representative_observation_id': representative['observation_id']}
                if anchor:
                    evidence['strong_anchor'] = dict(zip(('account_alias', 'conversation_id',
                        'sender_id', 'direction', 'message_type', 'server_id'), anchor))
                desired['message_link'].append((member['observation_id'], logical_id, RULE_VERSION,
                    'strong_server_identity' if anchor else 'unmerged_observation',
                    'strong' if anchor else 'none', _json(evidence)))
        desired['dedupe_candidate'] = self._candidates(observations)
        return {name: sorted(rows) for name, rows in desired.items()}
