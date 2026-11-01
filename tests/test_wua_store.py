"""Synthetic-only regression suite: no account database, key or media is read."""

import base64
from contextlib import closing
from copy import deepcopy
import hashlib
import itertools
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from wua import ArchiveStore, RULE_VERSION


SOURCE_A = {"source_id": "synthetic-pc-a", "device_alias": "fixture-a", "platform": "synthetic"}
SOURCE_B = {"source_id": "synthetic-pc-b", "device_alias": "fixture-b", "platform": "synthetic"}
SNAPSHOT_A = {"snapshot_id": "fixture-snapshot-a", "consistency": "synthetic", "completeness": "unknown"}
SNAPSHOT_B = {"snapshot_id": "fixture-snapshot-b", "consistency": "synthetic", "completeness": "unknown"}


def observation(**changes):
    result = {
        "account_alias": "synthetic-account", "conversation_id": "wxid_fixture_conversation",
        "sender_id": "wxid_fixture_sender", "direction": "incoming",
        "event_time": "2024-05-03T12:34:56+08:00", "raw_time": 1714710896,
        "time_unit": "seconds", "message_type": 1, "server_id": "18446744073709551615",
        "db_relative_path": "db/消息.sqlite", "table_name": "fixture_message",
        "native_locator": {"rowid": 1}, "body_text": "合成消息 alpha needle",
        "time_zone": "Asia/Shanghai", "time_precision": "second", "time_confidence": "adapter-declared",
    }
    result.update(changes)
    if "raw_record" not in result:
        result["raw_record"] = deepcopy(result)
    return result


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WuaStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wua-synthetic-")
        self.root = Path(self.temporary.name)
        self.path = self.root / "fixture.sqlite"
        self.store = ArchiveStore(self.path)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def add_a(self, rows):
        return self.store.import_observations(SOURCE_A, SNAPSHOT_A, rows)

    def add_b(self, rows):
        return self.store.import_observations(SOURCE_B, SNAPSHOT_B, rows)

    def test_strong_server_identity_links_without_deleting_observations(self):
        self.add_a([observation()])
        result = self.add_b([observation(native_locator={"rowid": 99})])
        self.assertEqual(result["totals"]["observations"], 2)
        self.assertEqual(result["totals"]["logical_messages"], 1)
        self.assertEqual(result["totals"]["automatic_duplicate_links"], 1)
        message = self.store.list_messages()[0]
        self.assertEqual(message["source_count"], 2)
        self.assertEqual(message["snapshot_count"], 2)
        self.assertEqual(message["server_id"], "18446744073709551615")
        observations = self.store.get_observations(message["logical_id"])
        self.assertEqual({item["source_id"] for item in observations},
                         {SOURCE_A["source_id"], SOURCE_B["source_id"]})
        self.assertTrue(all(item["rule_name"] == "strong_server_identity" for item in observations))
        self.assertEqual(observations[0]["dedupe_evidence"]["representative_rule"],
                         "lexicographic_min_observation_id")

    def test_identical_replay_and_rebuild_do_not_change_any_database_bytes(self):
        rows = [observation(), observation(native_locator=0, server_id=0)]
        self.add_a(rows)
        initial_hash, initial_digest = file_hash(self.path), self.store.semantic_digest()
        result = self.add_a(reversed(rows))
        self.assertEqual(result["added_observations"], 0)
        self.assertEqual(result["replayed_observations"], 2)
        self.assertTrue(result["idempotent_replay"])
        self.assertFalse(result["rebuild_changed"])
        self.assertFalse(self.store.rebuild_logical()["rebuild_changed"])
        self.assertEqual(file_hash(self.path), initial_hash)
        self.assertEqual(self.store.semantic_digest(), initial_digest)
        self.assertFalse(self.path.with_name(self.path.name + "-journal").exists())
        self.store.close()
        self.store = ArchiveStore(self.path)
        self.assertEqual(file_hash(self.path), initial_hash)
        self.add_a(rows)
        self.assertEqual(file_hash(self.path), initial_hash)

    def test_duplicate_in_same_batch_is_only_written_once(self):
        row = observation()
        result = self.add_a([row, deepcopy(row)])
        self.assertEqual(result["added_observations"], 1)
        self.assertEqual(result["replayed_observations"], 1)
        self.assertEqual(result["totals"]["observations"], 1)

    def test_import_order_has_identical_ids_stats_and_semantic_digest(self):
        batches = [
            (SOURCE_A, SNAPSHOT_A, [observation(), observation(native_locator=2, server_id=0)]),
            (SOURCE_B, SNAPSHOT_B, [observation(native_locator=-3), observation(
                native_locator=0, server_id=None, conversation_id=None)]),
            (SOURCE_A, {"snapshot_id": "snapshot-late"}, [observation(
                native_locator=0, event_time="2001-01-01T00:00:00Z", server_id=8)])]
        results = []
        for index, order in enumerate(itertools.permutations(batches)):
            with ArchiveStore(self.root / f"order-{index}.sqlite") as store:
                for source, snapshot, rows in order:
                    store.import_observations(source, snapshot, reversed(rows))
                results.append((store.semantic_digest(), store.stats(),
                    store.list_messages(), store.list_candidates(), store.get_conflicts(), store.coverage()))
        self.assertTrue(all(result == results[0] for result in results))

    def test_late_old_message_zero_and_negative_native_ids_are_not_skipped(self):
        self.add_a([observation(native_locator=100, server_id=100)])
        result = self.add_a([
            observation(native_locator=0, server_id=0, event_time="2000-01-01T00:00:00Z"),
            observation(native_locator=-9, server_id=0, event_time="2000-01-02T00:00:00Z")])
        self.assertEqual(result["added_observations"], 2)
        messages = self.store.list_messages()
        self.assertEqual(messages[0]["event_time"], "2000-01-01T00:00:00.000000Z")
        self.assertEqual(messages[1]["event_time"], "2000-01-02T00:00:00.000000Z")
        self.assertEqual(self.store.get_observations(messages[0]["logical_id"])[0]["native_locator"], 0)
        self.assertEqual(self.store.get_observations(messages[1]["logical_id"])[0]["native_locator"], -9)

    def test_revised_raw_row_adds_observation_and_auditable_content_conflict(self):
        first, revised = observation(), observation(body_text="修订正文 beta")
        self.add_a([first])
        result = self.add_a([revised])
        self.assertEqual(result["revised_observations"], 1)
        self.assertEqual(result["totals"]["observations"], 2)
        self.assertEqual(result["totals"]["logical_messages"], 1)
        conflict = self.store.get_conflicts()[0]
        self.assertEqual(conflict["field"], "body_text")
        self.assertEqual({item["value"] for item in conflict["values"]},
                         {first["body_text"], revised["body_text"]})
        self.assertEqual(len(self.store.list_messages(conflicts_only=True)), 1)
        self.assertEqual(len(self.store.list_messages(search="修订正文")), 1)
        self.assertEqual(len(self.store.list_messages(search="needle")), 1)
        self.assertEqual(len(self.store.get_observations(conflict["logical_id"])), 2)
        prior = file_hash(self.path)
        self.add_a([revised, first])
        self.assertEqual(file_hash(self.path), prior)

    def test_server_time_conflict_is_retained_with_raw_times(self):
        self.add_a([observation()])
        self.add_b([observation(event_time="2024-05-03T04:34:57.123456Z", raw_time=1714710897123,
                                time_unit="milliseconds")])
        self.assertEqual([item["field"] for item in self.store.get_conflicts()], ["event_time"])
        records = self.store.get_observations(self.store.list_messages()[0]["logical_id"])
        self.assertEqual({item["time_unit"] for item in records}, {"seconds", "milliseconds"})
        self.assertTrue(any(item["raw_time"] == 1714710897123 for item in records))

    def test_binary_original_columns_are_lossless_and_hashed(self):
        blob = bytes(range(256)) + b"\0\xff"
        raw = {"rowid": 0, "blob": blob, "nested": [memoryview(b"nested"), {"x": bytearray(b"bytes")}],
               "unicode": "原始值", "huge_integer": 2 ** 90}
        self.add_a([observation(raw_record=raw)])
        record = self.store.get_observations(self.store.list_messages()[0]["logical_id"])[0]
        binary = record["raw_record"]["blob"]["$wua_binary"]
        self.assertEqual(base64.b64decode(binary["data"]), blob)
        self.assertEqual(binary["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(binary["byte_length"], len(blob))
        self.assertEqual(record["raw_record"]["huge_integer"], 2 ** 90)
        self.assertEqual(record["row_hash"], hashlib.sha256(record["raw_record_json"].encode()).hexdigest())
        self.assertEqual(record["normalized_input"]["time_zone"], "Asia/Shanghai")

    def test_observation_identity_binds_every_required_locator_component(self):
        rows = [observation(server_id=0), observation(server_id=0, db_relative_path="other.db"),
                observation(server_id=0, table_name="other_table"),
                observation(server_id=0, native_locator={"rowid": 2}),
                observation(server_id=0, body_text="a revised original row")]
        self.add_a(rows)
        self.store.import_observations(SOURCE_A, {"snapshot_id": "another-snapshot"}, [rows[0]])
        self.assertEqual(self.store.stats()["observations"], 6)
        identifiers = [self.store.get_observations(item["logical_id"])[0]["observation_id"]
                       for item in self.store.list_messages()]
        self.assertEqual(len(set(identifiers)), 6)

    def test_cross_account_conversation_sender_type_direction_mismatches_do_not_merge(self):
        base = observation()
        rows = [base, observation(native_locator=2, account_alias="other-account"),
                observation(native_locator=3, conversation_id="other@chatroom"),
                observation(native_locator=4, sender_id="wxid_another"),
                observation(native_locator=5, message_type=49),
                observation(native_locator=6, direction="outgoing")]
        self.add_a(rows)
        self.assertEqual(self.store.stats()["logical_messages"], 6)
        self.assertEqual(self.store.stats()["automatic_duplicate_links"], 0)

    def test_missing_or_unknown_identity_never_auto_merges(self):
        for field in ("account_alias", "conversation_id", "sender_id", "direction", "message_type"):
            for unknown in (None, "", "unknown", "unresolved", 0, -1):
                with self.subTest(field=field, unknown=unknown), ArchiveStore(":memory:") as store:
                    store.import_observations(SOURCE_A, SNAPSHOT_A, [observation(**{field: unknown})])
                    store.import_observations(SOURCE_B, SNAPSHOT_B, [observation(**{field: unknown})])
                    self.assertEqual(store.stats()["logical_messages"], 2)

    def test_display_name_is_not_a_stable_conversation_identifier(self):
        self.add_a([observation(conversation_id="同名群聊")])
        self.add_b([observation(conversation_id="同名群聊")])
        self.assertEqual(self.store.stats()["logical_messages"], 2)

    def test_explicit_adapter_stable_id_opt_in_and_opt_out(self):
        for value, flag, expected in (("opaque-stable-id", True, 1),
                                      ("wxid_fixture", False, 2)):
            with self.subTest(flag=flag), ArchiveStore(":memory:") as store:
                row = observation(conversation_id=value, conversation_id_is_stable=flag)
                store.import_observations(SOURCE_A, SNAPSHOT_A, [row])
                store.import_observations(SOURCE_B, SNAPSHOT_B, [row])
                self.assertEqual(store.stats()["logical_messages"], expected)

    def test_incomplete_identity_prefixes_are_not_stable(self):
        for identity in ("wxid_", "gh_", "@chatroom"):
            with self.subTest(identity=identity), ArchiveStore(":memory:") as store:
                row = observation(conversation_id=identity)
                store.import_observations(SOURCE_A, SNAPSHOT_A, [row])
                store.import_observations(SOURCE_B, SNAPSHOT_B, [row])
                self.assertEqual(store.stats()["logical_messages"], 2)

    def test_invalid_or_zero_server_ids_never_auto_merge(self):
        for server_id in (None, 0, "0", "000", "+0", "-0", False, 1.0, "not-a-server-id"):
            with self.subTest(server_id=server_id), ArchiveStore(":memory:") as store:
                row = observation(server_id=server_id)
                store.import_observations(SOURCE_A, SNAPSHOT_A, [row])
                store.import_observations(SOURCE_B, SNAPSHOT_B, [row])
                self.assertEqual(store.stats()["logical_messages"], 2)

    def test_repeated_same_second_text_is_medium_candidate_only(self):
        self.add_a([observation(native_locator=index, server_id=0, body_text="好的") for index in (1, 2, 3)])
        self.assertEqual(self.store.stats()["logical_messages"], 3)
        self.assertEqual(self.store.stats()["automatic_duplicate_links"], 0)
        candidates = self.store.list_candidates(confidence="medium")
        self.assertEqual(len(candidates), 3)
        self.assertTrue(all(not item["evidence"]["automatic_merge"] for item in candidates))

    def test_weak_candidate_preserves_unknown_conversation(self):
        self.add_a([observation(server_id=0, conversation_id=None)])
        self.add_b([observation(server_id=0, conversation_id=None)])
        self.assertEqual(self.store.stats()["logical_messages"], 2)
        self.assertEqual(len(self.store.list_candidates(confidence="weak")), 1)

    def test_explicitly_different_server_ids_are_not_text_candidates(self):
        self.add_a([observation(server_id=1)])
        self.add_b([observation(server_id=2)])
        self.assertEqual(self.store.stats()["logical_messages"], 2)
        self.assertEqual(self.store.stats()["candidates"], 0)

    def test_candidate_window_and_unicode_whitespace_normalization(self):
        self.add_a([observation(server_id=0, body_text="cafe\u0301  body")])
        self.add_b([observation(server_id=0, body_text="café\t body", event_time="2024-05-03T04:34:58Z")])
        self.assertEqual(len(self.store.list_candidates()), 1)
        self.assertEqual(self.store.list_candidates()[0]["evidence"]["time_delta_microseconds"], 2_000_000)
        self.store.import_observations(SOURCE_A, {"snapshot_id": "outside-window"}, [
            observation(server_id=0, body_text="café body", event_time="2024-05-03T04:35:01Z")])
        self.assertEqual(len(self.store.list_candidates()), 1)

    def test_metadata_conflicts_are_atomic_and_leave_file_bytes_unchanged(self):
        self.add_a([observation()])
        before = file_hash(self.path)
        with self.assertRaisesRegex(ValueError, "source metadata"):
            self.store.import_observations({**SOURCE_A, "platform": "changed"}, SNAPSHOT_A, [])
        with self.assertRaisesRegex(ValueError, "snapshot metadata"):
            self.store.import_observations(SOURCE_B, SNAPSHOT_A, [])
        self.assertEqual(self.store.stats()["sources"], 1)
        self.assertEqual(file_hash(self.path), before)

    def test_partial_generator_failure_rolls_back_all_layers_and_metadata(self):
        self.add_a([observation()])
        before = file_hash(self.path)

        def broken_rows():
            yield observation(server_id=88)
            raise RuntimeError("synthetic adapter failure")

        with self.assertRaisesRegex(RuntimeError, "adapter failure"):
            self.add_b(broken_rows())
        self.assertEqual(self.store.stats()["sources"], 1)
        self.assertEqual(self.store.stats()["snapshots"], 1)
        self.assertEqual(self.store.stats()["observations"], 1)
        self.assertEqual(file_hash(self.path), before)

    def test_rebuild_failure_rolls_back_import_and_keeps_original_derived_layer(self):
        self.add_a([observation()])
        before = file_hash(self.path)
        with patch.object(self.store, "_rebuild", side_effect=RuntimeError("synthetic rebuild failure")):
            with self.assertRaises(RuntimeError):
                self.add_b([observation(server_id=99)])
        self.assertEqual(file_hash(self.path), before)
        self.assertEqual(self.store.stats()["logical_messages"], 1)

    def test_changed_interpretation_cannot_overwrite_existing_raw_observation(self):
        row = observation()
        self.add_a([row])
        before = file_hash(self.path)
        changed = {**row, "body_text": "different interpretation", "message_type": 49}
        with self.assertRaisesRegex(ValueError, "normalised interpretation"):
            self.add_a([changed])
        self.assertEqual(file_hash(self.path), before)
        self.assertEqual(self.store.list_messages()[0]["body_text"], row["body_text"])

    def test_raw_dictionary_key_order_is_canonical_and_idempotent(self):
        row = observation(raw_record={"b": 2, "a": 1})
        self.add_a([row])
        before = file_hash(self.path)
        replay = deepcopy(row)
        replay["raw_record"] = {"a": 1, "b": 2}
        self.assertTrue(self.add_a([replay])["idempotent_replay"])
        self.assertEqual(file_hash(self.path), before)

    def test_snapshot_and_source_metadata_are_retained_and_no_completeness_is_inferred(self):
        snapshot = {**SNAPSHOT_A, "unparsed_databases": ["not-open.db"], "completeness": "unknown"}
        self.store.import_observations(SOURCE_A, snapshot, [observation()])
        report = self.store.coverage()
        self.assertEqual(report["status"], "observed_rows_only")
        self.assertIsNone(report["unparsed_rows"])
        self.assertEqual(report["sources"][0]["snapshot_meta"], snapshot)
        self.assertEqual(report["sources"][0]["source_meta"], SOURCE_A)
        self.assertEqual(report["sources"][0]["acquisition_completeness"], "not_assessed")
        self.assertEqual(report["matrix"][0]["month_utc"], "2024-05")

    def test_empty_source_is_reported_unknown_not_complete(self):
        result = self.add_a([])
        self.assertEqual(result["totals"]["observations"], 0)
        self.assertEqual(self.store.coverage()["sources"][0]["coverage_status"], "observed_rows_only")
        before = file_hash(self.path)
        self.assertTrue(self.add_a([])["idempotent_replay"])
        self.assertEqual(file_hash(self.path), before)

    def test_readonly_pagination_filters_search_and_expansion_never_write(self):
        self.add_a([observation(), observation(native_locator=2, server_id=2, message_type=49,
            event_time="2024-06-03T00:00:00Z", body_text="quote %_\\ literal")])
        self.add_b([observation(native_locator=8)])
        before = file_hash(self.path)
        with ArchiveStore(self.path, readonly=True) as reader:
            self.assertEqual(len(reader.list_messages(limit=1)), 1)
            self.assertEqual(len(reader.list_messages(limit=1, offset=1)), 1)
            self.assertEqual(reader.list_messages(offset=2), [])
            self.assertEqual(len(reader.list_messages(source_id=SOURCE_B["source_id"])), 1)
            self.assertEqual(len(reader.list_messages(snapshot_id=SNAPSHOT_B["snapshot_id"])), 1)
            self.assertEqual(len(reader.list_messages(message_type=49)), 1)
            self.assertEqual(len(reader.list_messages(since="2024-06-01T00:00:00Z")), 1)
            self.assertEqual(len(reader.list_messages(until="2024-06-01T00:00:00Z")), 1)
            self.assertEqual(reader.list_messages(conversation_id="not-present"), [])
            self.assertEqual(len(reader.list_messages(search="%_\\")), 1)
            self.assertEqual(len(reader.list_messages(search="成消息")), 1)
            self.assertEqual(len(reader.list_messages(search="alpha needle")), 1)
            self.assertEqual(len(reader.list_messages(search="NEEDLE")), 1)
            self.assertEqual(len(reader.get_observations(reader.list_messages()[0]["logical_id"])), 2)
            self.assertEqual(reader.integrity_check(), {"quick_check": ["ok"], "foreign_key_check": []})
            reader.coverage()
            reader.semantic_digest()
            reader.list_candidates()
            reader.get_conflicts()
            with self.assertRaises(PermissionError):
                reader.import_observations(SOURCE_A, SNAPSHOT_A, [])
            with self.assertRaises(PermissionError):
                reader.rebuild_logical()
        self.assertEqual(file_hash(self.path), before)

    def test_fts_is_optional_and_does_not_change_semantic_digest_or_search(self):
        class NoFtsStore(ArchiveStore):
            def _create_fts(self):
                pass

        row = observation(body_text="用于全文检索 synthetic needle")
        self.add_a([row])
        with NoFtsStore(self.root / "no-fts.sqlite") as store:
            store.import_observations(SOURCE_A, SNAPSHOT_A, [row])
            self.assertFalse(store.fts_enabled)
            self.assertEqual(store.semantic_digest(), self.store.semantic_digest())
            for search in ("needle", "全文检索", "文", "%", '"', "SYNTHETIC"):
                self.assertEqual(store.list_messages(search=search), self.store.list_messages(search=search))

    def test_unknown_times_sort_last_and_original_precision_is_retained(self):
        self.add_a([observation(native_locator=0, server_id=0, event_time=None, raw_time="unparsed"),
                    observation(native_locator=-1, server_id=0)])
        messages = self.store.list_messages()
        self.assertIsNone(messages[-1]["event_time"])
        record = self.store.get_observations(messages[-1]["logical_id"])[0]
        self.assertEqual(record["raw_time"], "unparsed")
        self.assertEqual(record["normalized_input"]["time_precision"], "second")
        self.assertIn("unknown", [item["month_utc"] for item in self.store.coverage()["matrix"]])

    def test_timezone_equivalence_is_not_a_false_conflict(self):
        self.add_a([observation()])
        self.add_b([observation(event_time="2024-05-03T04:34:56Z")])
        self.assertEqual(self.store.get_conflicts(), [])

    def test_invalid_rows_and_escaping_paths_rollback_cleanly(self):
        for path in ("../escape.db", "db/../../escape.db", "C:\\absolute.db",
                     "\\\\server\\share\\db", "/absolute.db", "db/file.db:stream", ".", "bad\x00.db"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.add_a([observation(db_relative_path=path)])
        self.assertEqual(self.store.stats()["sources"], 0)
        self.assertEqual(self.store.stats()["observations"], 0)
        with self.assertRaises(ValueError):
            self.add_a([observation(event_time="2024-05-03T04:34:56")])
        with self.assertRaises(ValueError):
            self.add_a([observation(raw_record={"invalid": float("nan")})])
        with self.assertRaises(TypeError):
            self.add_a([observation(raw_record={1: "non-string JSON key"})])
        self.assertEqual(self.store.stats()["observations"], 0)

    def test_protected_observations_and_metadata_cannot_be_updated_or_deleted(self):
        self.add_a([observation()])
        with closing(sqlite3.connect(self.path)) as connection, connection:
            for statement in ("DELETE FROM message_observation", "UPDATE message_observation SET body_text='x'",
                              "DELETE FROM source_snapshot", "DELETE FROM source_device",
                              "UPDATE source_snapshot SET metadata_json='{}'",
                              "UPDATE source_device SET metadata_json='{}'"):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)
        self.assertEqual(self.store.integrity_check(), {"quick_check": ["ok"], "foreign_key_check": []})

    def test_rebuild_recovers_deleted_derived_layer_from_immutable_observations(self):
        self.add_a([observation()])
        self.add_b([observation(body_text="conflicting body")])
        digest, messages = self.store.semantic_digest(), self.store.list_messages()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("PRAGMA foreign_keys=ON")
            for table in ("dedupe_candidate", "conflict", "message_link", "logical_message"):
                connection.execute(f"DELETE FROM {table}")
        self.assertTrue(self.store.rebuild_logical()["rebuild_changed"])
        self.assertEqual(self.store.semantic_digest(), digest)
        self.assertEqual(self.store.list_messages(), messages)
        self.assertEqual(self.store.integrity_check(), {"quick_check": ["ok"], "foreign_key_check": []})

    def test_rebuild_repairs_fts_content_without_changing_semantic_digest(self):
        self.add_a([observation()])
        if not self.store.fts_enabled:
            self.skipTest("SQLite was built without FTS5")
        initial = self.store.semantic_digest()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DELETE FROM message_fts")
        self.assertTrue(self.store.rebuild_logical()["rebuild_changed"])
        self.assertEqual(len(self.store.list_messages(search="needle")), 1)
        self.assertEqual(self.store.semantic_digest(), initial)
        prior = file_hash(self.path)
        self.assertFalse(self.store.rebuild_logical()["rebuild_changed"])
        self.assertEqual(file_hash(self.path), prior)

    def test_foreign_database_is_refused_without_changing_bytes(self):
        path = self.root / "foreign.sqlite"
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("CREATE TABLE unrelated (value TEXT)")
            connection.execute("INSERT INTO unrelated VALUES ('preserve me')")
        before = file_hash(path)
        with self.assertRaisesRegex(ValueError, "foreign database"):
            ArchiveStore(path)
        self.assertEqual(file_hash(path), before)

    def test_unsupported_rule_and_invalid_pagination_are_rejected(self):
        self.add_a([observation()])
        before = file_hash(self.path)
        with self.assertRaises(ValueError):
            self.store.rebuild_logical(rule_version=RULE_VERSION + "-not-implemented")
        for invalid in (0, -1, 1001, True, "1"):
            with self.subTest(limit=invalid), self.assertRaises(ValueError):
                self.store.list_messages(limit=invalid)
        self.assertEqual(file_hash(self.path), before)


if __name__ == "__main__":
    unittest.main()
