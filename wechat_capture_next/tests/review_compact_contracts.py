"""Independent synthetic review probes; never read a real archive or catalog.

Run explicitly: python -m unittest wechat_capture_next.tests.review_compact_contracts -v
The indexed-locator and same-group tests are acceptance contracts, not assertions
that the review-time quadratic behavior should be preserved.
"""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tests.test_wua_store import observation
from wua.store import _json
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.compact_delta import rebuild_delta
from wechat_capture_next.content_pool import register_codec, render_text


def _append(archive, count, *, body='synthetic strong message'):
    archive.insert_source_exact('synthetic', _json({'source_id': 'synthetic'}))
    archive.insert_snapshot_exact('snapshot', 'synthetic', _json({'snapshot_id': 'snapshot'}))
    for number in range(count):
        archive.insert_prepared(archive.prepared_observation('snapshot',
            observation(native_locator=number, server_id=1, body_text=body)))


class IndependentCompactReview(unittest.TestCase):
    def test_indexed_locator_does_not_decode_prior_corpus_for_each_new_or_replayed_row(self):
        count = 80
        with CompactArchive(':memory:', fts=False) as archive:
            decoded = [0]

            def render(*args):
                value = render_text(*args)
                if value.isdigit() and int(value) < count:
                    decoded[0] += 1
                return value

            archive._db.create_function('next_content_render', 4, render, deterministic=True)
            rows = [observation(native_locator=i, server_id=i+1, body_text='body '+str(i))
                    for i in range(count)]
            metadata = ({'source_id': 'synthetic'}, {'source_id': 'synthetic', 'snapshot_id': 'snapshot'})
            archive.import_observations(*metadata, rows)
            initial_decodes = decoded[0]
            decoded[0] = 0
            before = archive._db.total_changes
            archive.import_observations(*metadata, rows)
            replay_decodes = decoded[0]
            self.assertEqual(before, archive._db.total_changes)
            self.assertLessEqual(initial_decodes, 3*count,
                f'new locator query decoded {initial_decodes} values for {count} rows')
            self.assertLessEqual(replay_decodes, 3*count,
                f'exact replay decoded {replay_decodes} locators for {count} rows')

    def test_candidate_lookup_prunes_members_of_the_same_strong_group_before_decoding(self):
        with CompactArchive(':memory:', fts=False) as archive:
            with archive.transaction():
                _append(archive, 80)
                result = rebuild_delta(archive, archive.new_observation_ids)
                self.assertEqual(result['totals']['logical_messages'], 1)
                self.assertEqual(result['totals']['candidates'], 0)
                self.assertEqual(archive.last_rebuild_reads['neighbor_pairs'], 0,
                    'same-logical-group pairs cannot be candidates and need not be decoded')

    def test_two_complete_attached_archives_keep_recipe_ids_local(self):
        with tempfile.TemporaryDirectory(prefix='next-compact-review-') as root:
            expected = {}
            for index, name in enumerate(('left', 'right')):
                path = Path(root)/(name+'.sqlite')
                with CompactArchive(path, create=True) as archive:
                    body = (name+' quoted "正文\\\n🙂')*120
                    archive.import_observations({'source_id': name}, {'snapshot_id': name},
                        [observation(body_text=body, raw_record={'body': body, 'binary': bytes(range(64))})])
                    self.assertGreater(archive.storage_stats()['canonical_json_recipes'], 0)
                    expected[name] = tuple(archive._db.execute('''SELECT raw_record_json,normalized_json,body_text
                        FROM message_observation''').fetchone())
            with closing(sqlite3.connect(':memory:', uri=True)) as reader:
                register_codec(reader)
                for name in ('left', 'right'):
                    reader.execute(f'ATTACH DATABASE ? AS {name}',
                        ((Path(root)/(name+'.sqlite')).as_uri()+'?mode=ro',))
                for name in ('right', 'left', 'right'):
                    actual = tuple(reader.execute(f'''SELECT raw_record_json,normalized_json,body_text
                        FROM {name}.message_observation''').fetchone())
                    self.assertEqual(actual, expected[name])

    def test_full_writable_integrity_rejects_empty_fts_and_explicit_repair_restores_it(self):
        with CompactArchive(':memory:') as archive:
            if archive.fts_tokenizer != 'trigram':
                self.skipTest('trigram FTS is unavailable')
            archive.import_observations({'source_id': 'synthetic'}, {'snapshot_id': 'snapshot'},
                [observation(body_text='synthetic searchable needle')])
            self.assertEqual(len(archive.list_messages(search='needle')), 1)
            archive._db.execute("INSERT INTO message_fts(message_fts) VALUES('delete-all')")
            self.assertEqual(archive.list_messages(search='needle'), [])
            # quick_check and pool/raw hashes alone are not search proof.
            self.assertEqual([row[0] for row in archive._db.execute('PRAGMA quick_check')], ['ok'])
            with self.assertRaises(sqlite3.DatabaseError):
                archive.integrity_check()
            self.assertFalse(archive._db.in_transaction)
            result = archive.rebuild_logical()
            self.assertTrue(result['search_index_repaired'])
            self.assertEqual(len(archive.list_messages(search='needle')), 1)
            checks = archive.integrity_check()
            self.assertTrue(checks['fts_verified'])
            self.assertEqual(checks['fts_status'], 'verified')

    def test_readonly_integrity_reports_fts_scope_without_rewriting_archive(self):
        with tempfile.TemporaryDirectory(prefix='next-compact-review-readonly-') as root:
            target = Path(root)/'archive.sqlite'
            with CompactArchive(target, create=True) as archive:
                archive.import_observations({'source_id': 'synthetic'}, {'snapshot_id': 'snapshot'},
                    [observation(body_text='read only searchable needle')])
                enabled = archive.fts_enabled
            before = target.read_bytes()
            with CompactArchive(target, readonly=True) as archive:
                checks = archive.integrity_check()
                self.assertFalse(checks['fts_verified'])
                self.assertEqual(checks['fts_status'], 'not_verified_readonly' if enabled else 'disabled')
                self.assertEqual(len(archive.list_messages(search='needle')), 1)
            self.assertEqual(before, target.read_bytes())

    def test_real_process_death_rolls_back_content_fts_projection_and_logical_writes(self):
        with tempfile.TemporaryDirectory(prefix='next-compact-review-crash-') as root:
            target = Path(root)/'archive.sqlite'
            with CompactArchive(target, create=True) as archive:
                archive.import_observations({'source_id': 'synthetic'}, {'snapshot_id': 'before'},
                    [observation(body_text='retained searchable needle')])
                before = archive.semantic_digest(), archive.storage_stats()
            script = r'''
import os, sys
from tests.test_wua_store import observation
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.compact_delta import rebuild_delta
from wua.store import _json
with CompactArchive(sys.argv[1]) as archive:
    apply = archive._apply_rows
    def crash(table, delta, *, delete=False):
        apply(table, delta, delete=delete)
        if table == 'logical_message' and not delete:
            os._exit(81)
    archive._apply_rows = crash
    with archive.transaction():
        archive.insert_snapshot_exact('during-crash', 'synthetic', _json({'snapshot_id':'during-crash'}))
        for i in range(40):
            archive.insert_prepared(archive.prepared_observation('during-crash',
                observation(native_locator=i, server_id=100+i, body_text='interrupted body '+str(i))))
        rebuild_delta(archive, archive.new_observation_ids)
raise AssertionError('fault injection was not reached')
'''
            result = subprocess.run([sys.executable, '-c', script, str(target)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 81, result.stdout+result.stderr)
            with CompactArchive(target) as archive:
                self.assertEqual((archive.semantic_digest(), archive.storage_stats()), before)
                self.assertEqual(archive._db.execute('SELECT count(*) FROM next_merge_projection').fetchone()[0], 1)
                self.assertEqual(archive._db.execute('SELECT count(*) FROM source_snapshot').fetchone()[0], 1)
                self.assertEqual(len(archive.list_messages(search='needle')), 1)
                self.assertEqual(archive.list_messages(search='interrupted'), [])
                self.assertEqual(archive.integrity_check()['foreign_key_check'], [])


if __name__ == '__main__':
    unittest.main()
