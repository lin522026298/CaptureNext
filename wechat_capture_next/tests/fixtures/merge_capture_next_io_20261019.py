"""Column-projection-only WUA memory optimization; same rules/search/schema.

The reducer is intentionally kept equivalent to the frozen baseline. It does
not redesign candidates or FTS. Unused original records remain on disk in the
archive, not in every Python observation dictionary during a full rebuild.
"""
from collections import defaultdict
from itertools import zip_longest
import json

from wua.store import ArchiveStore, RULE_VERSION, _DERIVED_TABLES, _hash, _json, _strong_key


class LeanArchiveStore(ArchiveStore):
    def _same_rows(self, query, desired):
        cursor = self._db.execute(query)
        try:
            for old, new in zip_longest(cursor, desired):
                if old is None or new is None or tuple(old) != new:
                    return False
            return True
        finally:
            cursor.close()

    def _rebuild(self):
        desired = self._desired_state()
        # Same tuple order as sorted(old_rows), without a second whole old
        # derived corpus in Python. Every table's first key is unique except
        # conflict, whose (logical_id,field) pair is unique.
        changed = any(not self._same_rows(f'SELECT * FROM {name} ORDER BY 1,2', desired[name])
                      for name in _DERIVED_TABLES)
        old_ids = self._db.execute('SELECT logical_id FROM logical_message ORDER BY logical_id')
        added = 0
        try:
            old = next(old_ids, (None,))[0]
            for row in desired['logical_message']:
                key = row[0]
                while old is not None and old < key:
                    old = next(old_ids, (None,))[0]
                added += int(old != key)
        finally:
            old_ids.close()
        fts_rows, fts_changed = [], False
        if self.fts_enabled:
            mapping = {row[0]: row[1] for row in desired['message_link']}
            bodies = defaultdict(set)
            for observation, body in self._db.execute('SELECT observation_id,body_text FROM message_observation'):
                if body:
                    bodies[mapping[observation]].add(body)
            fts_rows = [(logical_id, '\n'.join(sorted(values))) for logical_id, values in sorted(bodies.items())]
            fts_changed = not self._same_rows('SELECT logical_id,body_text FROM message_fts ORDER BY logical_id', fts_rows)
        if changed:
            for name in ('dedupe_candidate', 'conflict', 'message_link', 'logical_message'):
                self._db.execute(f'DELETE FROM {name}')
            for name in _DERIVED_TABLES:
                if desired[name]:
                    placeholders = ','.join('?' for _ in desired[name][0])
                    self._db.executemany(f'INSERT INTO {name} VALUES ({placeholders})', desired[name])
        if fts_changed:
            self._db.execute('DELETE FROM message_fts')
            self._db.executemany('INSERT INTO message_fts VALUES (?,?)', fts_rows)
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
