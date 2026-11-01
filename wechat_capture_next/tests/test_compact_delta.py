"""Synthetic full-oracle checks; no user catalog, archive or live source access."""
from copy import deepcopy
import random
import sqlite3
import unittest
from unittest.mock import patch

from tests.test_wua_store import observation
from wua.store import ArchiveStore, _json
from wechat_capture_next.merge import LeanArchiveStore
from wechat_capture_next.compact_delta import ensure_delta_schema, register_observation, rebuild_delta, TABLES
from wechat_capture_next.compact_archive import CompactArchive


class DeltaHarness(LeanArchiveStore):
    """Old physical schema adapter isolates the new reducer from compression.

    The real compact archive owns body-pool FTS. This harness updates equivalent
    legacy group FTS locally so its public search and FTS union have an oracle.
    """
    def __init__(self):
        super().__init__(':memory:')
        self._db.execute('BEGIN')
        ensure_delta_schema(self)
        self._db.execute('COMMIT')

    def add(self, source, snapshot, rows):
        db = self._db
        db.execute('BEGIN IMMEDIATE')
        try:
            source_json, snapshot_json = _json(source), _json(snapshot)
            for table, key, identity, text in (
                    ('source_device', 'source_id', source['source_id'], source_json),
                    ('source_snapshot', 'snapshot_id', snapshot['snapshot_id'], snapshot_json)):
                old = db.execute(f'SELECT metadata_json FROM {table} WHERE {key}=?', (identity,)).fetchone()
                if old and old[0] != text:
                    raise ValueError('immutable metadata')
            db.execute('INSERT OR IGNORE INTO source_device VALUES(?,?)', (source['source_id'], source_json))
            db.execute('INSERT OR IGNORE INTO source_snapshot VALUES(?,?,?)',
                (snapshot['snapshot_id'], source['source_id'], snapshot_json))
            new_ids = []
            for row in rows:
                prepared = self._prepare_row(snapshot['snapshot_id'], row)
                old = db.execute('SELECT * FROM message_observation WHERE observation_id=?',
                    (prepared['observation_id'],)).fetchone()
                if old:
                    if dict(old) != prepared:
                        raise ValueError('existing raw observation has a different normalised interpretation')
                    continue
                db.execute('INSERT INTO message_observation ('+','.join(prepared)+') VALUES ('+
                    ','.join('?' for _ in prepared)+')', tuple(prepared.values()))
                register_observation(self, prepared)
                new_ids.append(prepared['observation_id'])
            result = rebuild_delta(self, iter(new_ids))
            if self.fts_enabled:
                for (logical_id,) in db.execute('''SELECT DISTINCT p.logical_id
                        FROM next_delta_new n JOIN next_merge_projection p
                        ON p.observation_id=n.observation_id'''):
                    bodies = {r[0] for r in db.execute('''SELECT o.body_text FROM message_link l
                        JOIN message_observation o ON o.observation_id=l.observation_id
                        WHERE l.logical_id=?''', (logical_id,)) if r[0]}
                    wanted = '\n'.join(sorted(bodies)) if bodies else None
                    old = db.execute('SELECT rowid,body_text FROM message_fts WHERE logical_id=?',
                        (logical_id,)).fetchone()
                    if wanted is not None and not old:
                        db.execute('INSERT INTO message_fts VALUES(?,?)', (logical_id, wanted))
                    elif old and wanted != old[1]:
                        db.execute('UPDATE message_fts SET body_text=? WHERE rowid=?', (wanted, old[0]))
            db.execute('COMMIT')
            return result
        except BaseException:
            db.execute('ROLLBACK')
            raise


class CompactDeltaTests(unittest.TestCase):
    def setUp(self):
        self.full = ArchiveStore(':memory:')
        self.delta = DeltaHarness()
        self.addCleanup(self.full.close)
        self.addCleanup(self.delta.close)

    def compare(self):
        self.assertEqual(self.full.semantic_digest(), self.delta.semantic_digest())
        for table in TABLES:
            self.assertEqual(sorted(map(tuple, self.full._db.execute(f'SELECT * FROM {table}'))),
                             sorted(map(tuple, self.delta._db.execute(f'SELECT * FROM {table}'))), table)
        if self.full.fts_enabled:
            self.assertEqual(list(map(tuple, self.full._db.execute(
                'SELECT logical_id,body_text FROM message_fts ORDER BY logical_id'))),
                list(map(tuple, self.delta._db.execute(
                'SELECT logical_id,body_text FROM message_fts ORDER BY logical_id'))))
        self.assertFalse(list(self.delta._db.execute('PRAGMA foreign_key_check')))

    def add(self, snapshot, rows, source='synthetic'):
        source_meta = {'source_id': source}
        snapshot_meta = {'source_id': source, 'snapshot_id': snapshot}
        self.full.import_observations(source_meta, snapshot_meta, deepcopy(rows))
        result = self.delta.add(source_meta, snapshot_meta, deepcopy(rows))
        self.compare()
        return result

    def test_smaller_representative_conflicts_nonrepresentative_search_and_witness(self):
        rows = [observation(native_locator=1, server_id=500, sender_id='wxid_a', body_text='repeat'),
                observation(native_locator=2, server_id=500, sender_id='wxid_b', body_text='repeat')]
        self.add('base', rows)
        before = tuple(self.delta._db.execute('SELECT * FROM dedupe_candidate').fetchone())
        minimum = min(r[0] for r in self.delta._db.execute('SELECT observation_id FROM message_observation'))
        extra = observation(native_locator=1, server_id=500, sender_id='wxid_a', body_text='repeat')
        snapshot = next('extra-'+str(i) for i in range(1000)
                        if self.delta._prepare_row('extra-'+str(i), extra)['observation_id'] < minimum)
        self.add(snapshot, [extra], source='another-source')
        after = tuple(self.delta._db.execute('SELECT * FROM dedupe_candidate').fetchone())
        self.assertEqual(before[0], after[0])
        self.assertNotEqual(before[5], after[5])
        self.add('conflict', [observation(native_locator=-10, server_id=500, sender_id='wxid_a',
            body_text='nonrepresentative needle', event_time='2001-01-01T00:00:00Z')])
        self.assertEqual(self.full.list_messages(search='needle'), self.delta.list_messages(search='needle'))
        self.assertEqual(len(self.delta.get_conflicts()), 2)

    def test_cross_conversation_unknown_identity_and_exact_window(self):
        self.add('base', [observation(server_id=0, conversation_id='wxid_room_a',
            body_text='cafe\u0301  body')])
        self.add('edge', [observation(server_id=0, conversation_id=None,
            body_text='café\t body', event_time='2024-05-03T04:34:58Z')])
        self.assertEqual(len(self.delta.list_candidates(confidence='weak')), 1)
        self.add('outside', [observation(server_id=0, conversation_id='wxid_room_b',
            body_text='café body', event_time='2024-05-03T04:35:00.000001Z')])
        self.assertEqual(len(self.delta.list_candidates()), 1)
        for field in ('account_alias', 'conversation_id', 'sender_id', 'direction', 'message_type'):
            self.add('unknown-'+field, [observation(native_locator=i, **{field: 'unknown'}) for i in (1, 2)])
        self.assertEqual(self.delta.stats()['automatic_duplicate_links'], 0)

    def test_random_batches_match_full_all_derived_rows_and_order_independence(self):
        rng = random.Random(719)
        batches = []
        for batch in range(20):
            rows = []
            for index in range(7):
                rows.append(observation(native_locator=index-3,
                    account_alias=rng.choice(('account', 'account-2', 'unknown', None)),
                    conversation_id=rng.choice(('wxid_room', 'wxid_other', None, 'opaque')),
                    conversation_id_is_stable=rng.choice((True, False, None, 1)),
                    sender_id=rng.choice(('wxid_a', 'wxid_b', 'unknown', None)),
                    direction=rng.choice(('incoming', 'outgoing', None)),
                    message_type=rng.choice((1, 2, None)), server_id=rng.choice((0, 101, 102)),
                    body_text=rng.choice(('same', 'same\t  text', 'same text', 'café', 'cafe\u0301', '', ' ', None)),
                    event_time=rng.choice((None, 1700000000, 1700000001, 1700000002, 1700000002.000001))))
            batches.append(('batch-'+str(batch), rows))
        for snapshot, rows in batches:
            self.add(snapshot, rows)
        original = self.delta.semantic_digest()
        with type(self.delta)() as reverse:
            for snapshot, rows in reversed(batches):
                reverse.add({'source_id': 'synthetic'}, {'source_id': 'synthetic', 'snapshot_id': snapshot}, rows)
            self.assertEqual(original, reverse.semantic_digest())

    def test_small_append_reads_only_dirty_group_and_neighbor_window(self):
        self.add('base', [observation(native_locator=i, server_id=1000+i, body_text='unrelated '+str(i))
                          for i in range(500)])
        self.add('new', [observation(native_locator=-1, server_id=999999, body_text='one new body')])
        self.assertEqual(self.delta.last_rebuild_reads,
            {'dirty_groups': 1, 'group_observations': 1, 'neighbor_pairs': 0})
        self.assertEqual(self.delta.last_rebuild_writes['logical_message'], {'insert': 1, 'update': 0, 'delete': 0})
        query = '''EXPLAIN QUERY PLAN SELECT observation_id FROM next_merge_projection
            WHERE candidate_account=? AND candidate_body_hash=? AND time_us BETWEEN ? AND ?'''
        plan = ' '.join(str(tuple(row)) for row in self.delta._db.execute(query, ('a', 'b', 1, 2)))
        self.assertIn('next_merge_neighbor', plan)
        self.assertNotIn('SCAN next_merge_projection', plan)

    def test_replay_has_no_persistent_writes(self):
        rows = [observation()]
        self.add('base', rows)
        before = self.delta.semantic_digest()
        result = self.add('base', rows)
        self.assertEqual(before, self.delta.semantic_digest())
        self.assertFalse(result['rebuild_changed'])
        self.assertTrue(all(not any(counts.values()) for counts in self.delta.last_rebuild_writes.values()))
        self.assertEqual(self.delta.last_rebuild_reads['group_observations'], 0)

    def test_candidate_body_hash_collision_does_not_create_false_candidates(self):
        with patch('wechat_capture_next.compact_delta._body_hash', return_value='synthetic-collision'):
            self.add('collision-a', [observation(server_id=0, body_text='first body')])
            self.add('collision-b', [observation(server_id=0, body_text='different body')])
        self.assertEqual(self.delta.stats()['candidates'], 0)
        self.assertEqual(self.delta.last_rebuild_reads['neighbor_pairs'], 1)

    def test_new_new_pairs_once_but_new_old_pairs_are_all_preserved(self):
        self.add('pair-base', [observation(native_locator=i, server_id=0, body_text='repeat')
                               for i in range(3)])
        self.assertEqual(self.delta.last_rebuild_reads['neighbor_pairs'], 3)
        self.assertEqual(self.delta.stats()['candidates'], 3)
        self.add('pair-one', [observation(native_locator=0, server_id=0, body_text='repeat')])
        self.assertEqual(self.delta.last_rebuild_reads['neighbor_pairs'], 3)
        self.add('pair-two', [observation(native_locator=i, server_id=0, body_text='repeat')
                              for i in range(2)])
        # Two new x four old + one new/new pair; old observation IDs may be on
        # either side of the new IDs, so ID ordering alone would be incorrect.
        self.assertEqual(self.delta.last_rebuild_reads['neighbor_pairs'], 9)
        self.assertEqual(self.delta.stats()['candidates'], 15)

    def test_same_strong_group_bucket_does_not_do_quadratic_neighbor_work(self):
        source = {'source_id': 'synthetic'}
        snapshot = {'source_id': 'synthetic', 'snapshot_id': 'same-group'}
        costs = []
        for count in (80, 160, 320):
            rows = [observation(native_locator=i, server_id=500, body_text='all one strong group')
                    for i in range(count)]
            with type(self.delta)() as archive, ArchiveStore(':memory:') as full:
                steps, trace = [0], []

                def progress():
                    steps[0] += 100
                    return 0

                archive._db.set_progress_handler(progress, 100)
                archive._db.set_trace_callback(trace.append)
                try:
                    archive.add(source, snapshot, rows)
                finally:
                    archive._db.set_progress_handler(None, 0)
                    archive._db.set_trace_callback(None)
                costs.append(steps[0])
                self.assertEqual(archive.stats()['logical_messages'], 1)
                self.assertEqual(archive.stats()['candidates'], 0)
                self.assertEqual(archive.last_rebuild_reads['neighbor_pairs'], 0)
                checks = [sql for sql in trace if 'INDEXED BY next_merge_bucket_group' in sql]
                self.assertEqual(len(checks), 2)  # Once per bucket/group, not once per obs.
                self.assertFalse(any('p.time_us BETWEEN' in sql for sql in trace))
                full.import_observations(source, snapshot, rows)
                self.assertEqual(full.semantic_digest(), archive.semantic_digest())
        # Includes inserts, compression and group reduction. Doubling input
        # must not quadruple SQLite VM work for a bucket with zero candidates.
        self.assertLess(max(costs[i+1]/costs[i] for i in range(2)), 3)

    def test_failure_in_every_derived_phase_rolls_back_observations_projection_and_results(self):
        self.add('base', [observation()])
        before = self.delta.semantic_digest()
        projected = list(map(tuple, self.delta._db.execute('SELECT * FROM next_merge_projection')))
        for phase in TABLES:
            real = self.delta._apply_rows

            def fail(table, delta, *, delete=False):
                real(table, delta, delete=delete)
                if table == phase and not delete:
                    raise RuntimeError('synthetic phase failure')

            with self.subTest(phase=phase), patch.object(self.delta, '_apply_rows', side_effect=fail):
                with self.assertRaises(RuntimeError):
                    self.delta.add({'source_id': 'synthetic'},
                        {'source_id': 'synthetic', 'snapshot_id': 'failure'},
                        [observation(body_text='revised conflicting body')])
            self.assertEqual(before, self.delta.semantic_digest())
            self.assertEqual(projected, list(map(tuple, self.delta._db.execute('SELECT * FROM next_merge_projection'))))
        self.add('successful-retry', [observation(body_text='revised conflicting body')])

    def test_full_repair_remains_available_and_delta_missing_projection_fails_closed(self):
        self.add('base', [observation()])
        self.delta._db.execute('DELETE FROM message_link')
        self.delta._db.execute('DELETE FROM logical_message')
        self.delta.rebuild_logical()
        self.compare()
        self.delta._db.execute('BEGIN')
        try:
            with self.assertRaisesRegex(ValueError, 'missing merge projection'):
                rebuild_delta(self.delta, ['not-an-observation'])
        finally:
            self.delta._db.execute('ROLLBACK')


class RealCompactHarness(CompactArchive):
    def __init__(self):
        super().__init__(':memory:')

    def add(self, source, snapshot, rows):
        with self.transaction():
            self.insert_source_exact(source['source_id'], _json(source))
            self.insert_snapshot_exact(snapshot['snapshot_id'], source['source_id'], _json(snapshot))
            for row in rows:
                self.insert_prepared(self.prepared_observation(snapshot['snapshot_id'], row))
            return rebuild_delta(self, iter(self.new_observation_ids))


class RealCompactDeltaTests(CompactDeltaTests):
    """Run the same oracle matrix against the actual codec-enabled schema."""
    def setUp(self):
        self.full = ArchiveStore(':memory:')
        self.delta = RealCompactHarness()
        self.addCleanup(self.full.close)
        self.addCleanup(self.delta.close)

    def compare(self):
        self.assertEqual(self.full.semantic_digest(), self.delta.semantic_digest())
        for table in TABLES:
            self.assertEqual(sorted(map(tuple, self.full._db.execute(f'SELECT * FROM {table}'))),
                             sorted(map(tuple, self.delta._db.execute(f'SELECT * FROM {table}'))), table)
        bodies = {}
        for logical_id, body in self.delta._db.execute('''SELECT l.logical_id,o.body_text
                FROM message_link l JOIN message_observation o ON o.observation_id=l.observation_id'''):
            if body:
                bodies.setdefault(logical_id, set()).add(body)
        if self.full.fts_enabled:
            self.assertEqual(list(map(tuple, self.full._db.execute(
                'SELECT logical_id,body_text FROM message_fts ORDER BY logical_id'))),
                [(key, '\n'.join(sorted(values))) for key, values in sorted(bodies.items())])
        for term in ('needle', 'same', 'café', 'repeat', 'nonrepresentative', '%_', ' '):
            self.assertEqual(self.full.list_messages(search=term), self.delta.list_messages(search=term), term)
        self.assertFalse(list(self.delta._db.execute('PRAGMA foreign_key_check')))

    def test_full_repair_remains_available_and_delta_missing_projection_fails_closed(self):
        self.add('base', [observation()])
        self.delta._db.execute('DELETE FROM message_link')
        self.delta._db.execute('DELETE FROM logical_record')
        self.delta._db.execute('DELETE FROM next_merge_projection')
        self.delta.rebuild_logical()
        self.compare()
        with self.assertRaisesRegex(ValueError, 'archive transaction'):
            rebuild_delta(self.delta, [])
        with self.delta.transaction():
            with self.assertRaisesRegex(ValueError, 'missing merge projection'):
                rebuild_delta(self.delta, ['not-an-observation'])

    def test_dirty_rebuild_does_not_decode_raw_or_unused_normalized_payloads(self):
        from wechat_capture_next.content_pool import render_text, register_codec
        marker = 'synthetic-unused-payload-marker'
        self.add('large-base', [observation(native_locator=i, server_id=1000+i,
            body_text='body '+str(i), raw_record={'unused': marker*4000}, unused_hint=marker*4000)
            for i in range(80)])
        calls = []

        def checked_render(codec, data, size, atoms):
            text = render_text(codec, data, size, atoms)
            if marker in text:
                raise AssertionError('merge decoded an unused original/normalized payload')
            calls.append(size)
            return text

        self.delta._db.create_function('next_content_render', 4, checked_render, deterministic=True)
        with self.delta.transaction():
            snapshot = {'source_id': 'synthetic', 'snapshot_id': 'large-extra'}
            self.delta.insert_snapshot_exact(snapshot['snapshot_id'], snapshot['source_id'], _json(snapshot))
            row = observation(native_locator=-1, server_id=1000, body_text='extra body',
                raw_record={'unused': marker*4000}, unused_hint=marker*4000)
            self.delta.insert_prepared(self.delta.prepared_observation(snapshot['snapshot_id'], row))
            try:
                rebuild_delta(self.delta, self.delta.new_observation_ids)
            finally:
                register_codec(self.delta._db)
        self.assertEqual(self.delta.last_rebuild_reads['group_observations'], 2)
        self.assertGreater(len(calls), 0)
        self.assertLess(len(calls), 20)
        self.full.import_observations({'source_id': 'synthetic'}, snapshot, [row])
        self.compare()


if __name__ == '__main__':
    unittest.main()
