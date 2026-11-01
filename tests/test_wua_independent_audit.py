"""Independent audit regression: synthetic data only, never real archives."""
from contextlib import closing, redirect_stderr, redirect_stdout
import ast
import io
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

from tools import audit_wua_archive as independent
from wua import ArchiveStore


def observation(**changes):
    row = {
        "account_alias": "synthetic-account", "db_relative_path": "message/test.db",
        "table_name": "Msg_synthetic", "native_locator": {"rowid": 1, "local_id": 1},
        "raw_record": {"synthetic_id": 1, "blob": b"\x00\x01\xfe"},
        "conversation_id": "wxid_synthetic-peer", "sender_id": "wxid_synthetic-peer",
        "direction": "incoming", "server_id": 7001, "message_type": 1,
        "raw_time": 1700000000, "time_unit": "seconds", "event_time": 1700000000,
        "body_text": "synthetic text",
    }
    row.update(changes)
    return row


def add(store, source, rows):
    return store.import_observations(
        {"source_id": "synthetic-" + source},
        {"snapshot_id": "snapshot-" + source, "source_id": "synthetic-" + source}, rows)


class IndependentAuditAdversarialTests(unittest.TestCase):
    """The twelve adversarial checks from the sealed synthetic acceptance."""

    def verify(self, store):
        audit = independent.Audit()
        summary = independent.audit_archive(store._db, audit)
        self.assertEqual(dict(audit.failed), {})
        return summary

    def unresolved(self, field, value):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation(**{field: value})])
            add(store, "b", [observation(**{field: value})])
            summary = self.verify(store)
            self.assertEqual(store.stats()["logical_messages"], 2)
            self.assertEqual(store.stats()["candidates"], 1)
            self.assertEqual(summary["merge_metrics"]["cross_source_bridge_links"], 0)
            self.assertIs(store.list_candidates()[0]["evidence"]["automatic_merge"], False)

    def different_anchor_field(self, field, value):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation()])
            add(store, "b", [observation(**{field: value})])
            self.verify(store)
            self.assertEqual(store.stats()["logical_messages"], 2)
            self.assertEqual(store.stats()["conflicts"], 0)

    def test_same_full_anchor_body_and_time_conflicts_preserved(self):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation()])
            add(store, "b", [observation(body_text="other synthetic body", event_time=1700000040)])
            summary = self.verify(store)
            self.assertEqual(store.stats()["observations"], 2)
            self.assertEqual(store.stats()["logical_messages"], 1)
            self.assertEqual({c["field"] for c in store.get_conflicts()}, {"body_text", "event_time"})
            self.assertEqual(summary["merge_metrics"]["cross_source_bridge_links"], 1)
            self.assertEqual(summary["merge_metrics"]["within_source_extra_observations"], 0)

    def test_auditor_detects_corrupt_derived_count(self):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation()])
            self.verify(store)
            store._db.execute("UPDATE logical_message SET source_count=99")
            audit = independent.Audit()
            independent.audit_archive(store._db, audit)
            self.assertEqual(audit.failed["logical_aggregate_counts"], 1)

    def test_unknown_direction_is_not_automatically_merged(self):
        self.unresolved("direction", "unknown")

    def test_unknown_sender_is_not_automatically_merged(self):
        self.unresolved("sender_id", None)

    def test_zero_server_id_is_not_automatically_merged(self):
        self.unresolved("server_id", 0)

    def test_same_server_different_direction_stays_separate(self):
        self.different_anchor_field("direction", "outgoing")

    def test_same_server_different_sender_stays_separate(self):
        self.different_anchor_field("sender_id", "wxid_synthetic-other-peer")

    def test_same_server_different_type_stays_separate(self):
        self.different_anchor_field("message_type", 2)

    def test_within_source_duplicate_is_not_cross_source(self):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation(), observation(
                native_locator={"rowid": 2, "local_id": 2},
                raw_record={"synthetic_id": 2, "blob": b"\x02"})])
            summary = self.verify(store)
            self.assertEqual(store.stats()["logical_messages"], 1)
            self.assertEqual(summary["merge_metrics"]["cross_source_bridge_links"], 0)
            self.assertEqual(summary["merge_metrics"]["within_source_extra_observations"], 1)

    def test_snapshot_source_reassignment_rejected_atomically(self):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation()])
            before = store.semantic_digest()
            with self.assertRaises(ValueError):
                store.import_observations({"source_id": "synthetic-b"},
                    {"snapshot_id": "snapshot-a", "source_id": "synthetic-b"}, [observation()])
            self.assertEqual(store.semantic_digest(), before)
            self.verify(store)

    def test_generic_core_relies_on_adapter_direction_vocabulary(self):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation(direction="synthetic-other-direction")])
            add(store, "b", [observation(direction="synthetic-other-direction")])
            summary = self.verify(store)
            self.assertEqual(store.stats()["logical_messages"], 1)
            self.assertEqual(summary["direction_counts"], {"other": 2})

    def test_auditor_detects_corrupt_candidate_automatic_flag(self):
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation(server_id=0)])
            add(store, "b", [observation(server_id=0)])
            self.verify(store)
            candidate = store.list_candidates()[0]
            changed = candidate["evidence"]
            changed["automatic_merge"] = True
            store._db.execute("UPDATE dedupe_candidate SET evidence_json=? WHERE candidate_id=?",
                (json.dumps(changed, sort_keys=True, separators=(",", ":")), candidate["candidate_id"]))
            audit = independent.Audit()
            independent.audit_archive(store._db, audit)
            self.assertEqual(audit.failed["candidate_never_automatic"], 1)


class IndependentAuditCliSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "synthetic-archive.sqlite"
        self.output = self.root / "synthetic-audit.json"
        with ArchiveStore(self.archive) as store:
            add(store, "a", [observation()])

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *extra, archive=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ["--archive", str(archive or self.archive), "--output", str(self.output), *extra]
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = independent.main(args)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_cli_creates_report_without_private_values_and_preserves_input(self):
        before = independent.file_hash(self.archive)
        status, stdout, stderr = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        payload = self.output.read_text(encoding="utf-8")
        report = json.loads(payload)
        self.assertTrue(report["passed"])
        self.assertEqual(report["input_sha256"], before)
        self.assertEqual(independent.file_hash(self.archive), before)
        self.assertEqual(report["input_sha256_after"], before)
        for private_value in ("synthetic-account", "synthetic-a", "snapshot-a",
                              "wxid_synthetic-peer", "synthetic text", str(self.archive)):
            self.assertNotIn(private_value, payload + stdout + stderr)
        self.assertEqual(report["summary"]["source_observation_counts"],
            {independent.opaque_reference("source", "synthetic-a"): 1})

    def test_existing_output_refused_before_reading_input(self):
        self.output.write_bytes(b"synthetic-preserve-existing")
        with mock.patch.object(independent, "file_hash") as hashing:
            status, stdout, stderr = self.invoke(archive=self.root / "does-not-exist.sqlite")
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Refusing to overwrite", stderr)
        self.assertEqual(self.output.read_bytes(), b"synthetic-preserve-existing")
        hashing.assert_not_called()

    def test_exclusive_creation_refuses_output_race(self):
        original_hash = independent.file_hash
        calls = []

        def racing_hash(path):
            calls.append(path)
            if len(calls) == 2:
                self.output.write_bytes(b"synthetic-racing-writer")
            return original_hash(path)

        with mock.patch.object(independent, "file_hash", side_effect=racing_hash):
            status, stdout, stderr = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Refusing to overwrite", stderr)
        self.assertEqual(self.output.read_bytes(), b"synthetic-racing-writer")

    def test_nonempty_wal_and_journal_are_rejected(self):
        before = independent.file_hash(self.archive)
        for suffix in ("-wal", "-journal"):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(self.archive) + suffix)
                sidecar.write_bytes(b"synthetic-unfinished-sidecar")
                status, stdout, stderr = self.invoke()
                self.assertEqual(status, 2)
                self.assertEqual(stdout, "")
                self.assertIn("ValueError", stderr)
                self.assertFalse(self.output.exists())
                self.assertEqual(independent.file_hash(self.archive), before)
                sidecar.unlink()

    def test_open_frozen_rejects_writes(self):
        before = independent.file_hash(self.archive)
        connection = independent.open_frozen(self.archive)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("UPDATE archive_meta SET value='synthetic-change'")
        finally:
            connection.close()
        self.assertEqual(independent.file_hash(self.archive), before)

    def test_runtime_errors_omit_private_paths(self):
        missing = self.root / "synthetic-private-filename.sqlite"
        status, stdout, stderr = self.invoke(archive=missing)
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("FileNotFoundError", stderr)
        self.assertNotIn(str(missing), stderr)
        self.assertNotIn(missing.name, stderr)
        self.assertFalse(self.output.exists())

    def test_failed_checks_produce_status_one_without_modifying_input(self):
        with closing(sqlite3.connect(self.archive)) as connection, connection:
            connection.execute("UPDATE logical_message SET source_count=99")
        before = independent.file_hash(self.archive)
        status, stdout, stderr = self.invoke()
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertFalse(report["passed"])
        self.assertEqual(report["failed_check_counts"]["logical_aggregate_counts"], 1)
        self.assertEqual(independent.file_hash(self.archive), before)
        self.assertNotIn("synthetic text", stdout)
        self.assertTrue(all(value.startswith("ref_") for values in
            report["failure_samples_opaque_ids_only"].values() for value in values))

    def test_failure_samples_and_free_form_labels_are_not_echoed(self):
        audit = independent.Audit()
        private_marker = "synthetic-identifier-not-for-report"
        audit.check("synthetic_failure", False, private_marker)
        self.assertNotIn(private_marker, json.dumps(audit.samples))
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation(direction=private_marker, body_decode_status=private_marker)])
            summary = independent.audit_archive(store._db, independent.Audit())
        self.assertNotIn(private_marker, json.dumps(summary))
        self.assertEqual(summary["direction_counts"], {"other": 1})
        self.assertEqual(summary["decode_status_counts"], {"other": 1})

    def test_baseline_preservation_uses_only_readonly_synthetic_inputs(self):
        baseline = self.root / "synthetic-baseline.sqlite"
        shutil.copyfile(self.archive, baseline)
        before = independent.file_hash(baseline)
        with ArchiveStore(self.archive) as store:
            add(store, "b", [observation()])
        status, stdout, stderr = self.invoke("--baseline", str(baseline))
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(report["baseline_preservation"]["rows_checked"]["message_observation"], 1)
        self.assertTrue(report["baseline_preservation"]["unchanged"])
        self.assertEqual(independent.file_hash(baseline), before)
        self.assertNotIn(str(baseline), stdout)

    def test_native_counts_bind_database_fingerprint_without_filename(self):
        native_root = self.root / "synthetic-native"
        native_root.mkdir()
        native = native_root / "synthetic-private-db-name.db"
        table = "Msg_" + "a" * 32
        with closing(sqlite3.connect(native)) as connection, connection:
            connection.execute('CREATE TABLE "' + table + '" (payload BLOB)')
            connection.execute('INSERT INTO "' + table + '" VALUES (?)', (b"synthetic-blob",))
        native_hash = independent.file_hash(native)
        with ArchiveStore(":memory:") as store:
            add(store, "a", [observation(table_name=table, input_database_sha256=native_hash)])
            audit = independent.Audit()
            report = independent.native_counts("synthetic-a", native_root, store._db, audit)
            self.assertEqual(dict(audit.failed), {})
        self.assertTrue(report["counts_match"])
        self.assertEqual(report["native_counts"]["message_rows"], 1)
        self.assertEqual(report["message_databases"][0]["sha256"], native_hash)
        payload = json.dumps(report)
        self.assertNotIn(native.name, payload)
        self.assertNotIn("synthetic-a", payload)
        self.assertNotIn(str(native), payload)
        self.assertEqual(independent.file_hash(native), native_hash)

    def test_public_auditor_imports_only_standard_library(self):
        tree = ast.parse(Path(independent.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported, sys.stdlib_module_names | {"__future__"})
        self.assertNotIn("wua", imported)


if __name__ == "__main__":
    unittest.main()
