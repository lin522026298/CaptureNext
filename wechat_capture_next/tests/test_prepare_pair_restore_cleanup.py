"""Isolated synthetic paired restore planning; never accesses real archives."""
from collections import Counter
import copy
import ast
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager,ExitStack
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock

from wechat_capture_v2.common import digest_file
from wechat_capture_next import prepare_pair_restore_cleanup as helper
from wechat_capture_next import pair_repository as repo, rolling_delivery
from wechat_capture_next.tests import test_rolling_delivery as fixtures


@unittest.skipUnless(os.name == 'nt', 'Windows deny-write/delete planning contract')
class CleanupPlanTests(unittest.TestCase):
    setUp = fixtures.RollingDeliveryTests.setUp
    pages = fixtures.RollingDeliveryTests.pages
    publish = fixtures.RollingDeliveryTests.publish
    init_service = fixtures.RollingDeliveryTests.init_service
    prepared = fixtures.RollingDeliveryTests.prepared
    tearDown = fixtures.RollingDeliveryTests.tearDown

    def setup_pair(self, name='paired-A16-restored',legacy_identity_summary=False,legacy_media_binding=False):
        self.prepared()
        self.working = self.root/'working'/'wechat_product_20261022'
        self.working.mkdir(parents=True)
        self.repository = self.root/'retained-repository'
        with ExitStack() as older:
            from wechat_capture_next.compact_archive import CompactArchive
            current_check=CompactArchive.integrity_check
            def old_summary(archive):
                result=current_check(archive);result.pop('identities');return result
            if legacy_identity_summary:older.enter_context(patch.object(CompactArchive,'integrity_check',old_summary))
            options={}
            if legacy_media_binding:
                current_publish=repo.publish
                def old_publish(repository,owner,files,context,**kwargs):
                    original={k:context[k] for k in helper.REQUIRED_CONTEXT_FIELDS}
                    return current_publish(repository,owner,files,original,**kwargs)
                older.enter_context(patch.object(repo,'publish',side_effect=old_publish))
                options['object_block_bytes']=repo.MAX_BLOCK
            self.snapshot=rolling_delivery.backup(self.state,self.formal,self.repository,**options)['snapshot_id']
        self.expansion = self.working/name
        self.delivered = rolling_delivery.restore(self.repository, self.snapshot, self.expansion)
        self.measurement = self.working/'independent-restore-measurement.private.json'
        hashes = {'synthetic_fixture.py': hashlib.sha256(b'fixed synthetic fixture').hexdigest()}
        self.measured = dict(schema='next-paired-backup-measurement-1', partial=False, error_type=None,
            code_changed_during_run=False, result=self.delivered, space_scope=str(self.expansion),
            run=dict(action='restore', source_hashes=hashes), source_hashes_after=hashes)
        self.write_json(self.measurement, self.measured)
        self.lifecycle=self.working/'task-lifecycle.private.json'
        self.write_lifecycle(self.expansion)

    def write_lifecycle(self,target):
        self.write_json(self.lifecycle,dict(schema=helper.LIFECYCLE_SCHEMA,target=str(target),coverage_complete=True,
            processes=[dict(role='synthetic-owned-backend',pid=2147483500,create_time=None,exit_receipt=None)]))

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')

    def plan(self, **options):
        options.setdefault('restore_receipt', self.measurement)
        options.setdefault('lifecycle_receipt',self.lifecycle)
        with patch.object(helper.psutil, 'process_iter', return_value=[]),\
                patch.object(helper,'_process_identity',return_value=None):
            return helper.plan(self.expansion, self.repository, self.snapshot,
                _working_root=self.working, **options)

    def all_hashes(self):
        return {str(p): digest_file(p) for p in self.root.rglob('*') if p.is_file()}

    def test_success_is_readonly_one_hash_per_expansion_file_and_no_deletion(self):
        self.setup_pair(); before = self.all_hashes()
        with patch.object(helper, 'digest_file', wraps=digest_file) as hashing:
            result = self.plan()
        counts = Counter(Path(c.args[0]) for c in hashing.call_args_list)
        for row in result['inventory']['files']:
            self.assertEqual(counts[self.expansion/row['relative']], 1)
        self.assertEqual(before, self.all_hashes())
        self.assertTrue(result['plan_only']); self.assertFalse(result['deletion_executed'])
        self.assertFalse(result['deletion_authorized'])
        self.assertTrue(result['retained_repository_payload_verified_now']['verified'])
        self.assertTrue(result['attachment_closure']['attachments_closed'])
        self.assertEqual(result['snapshot_id'], self.snapshot)
        self.assertTrue(result['task_lifecycle_verified']);self.assertTrue(result['target_access_probe_passed'])
        self.assertFalse(result['global_dependency_absence_proven'])
        self.assertTrue(result['target_access_probe']['all_owned_probe_handles_closed'])

    def test_explicit_retained_full_repository_alternative_not_manifest_only(self):
        self.setup_pair()
        with self.assertRaisesRegex(ValueError, 'independent restore measurement'):
            self.plan(restore_receipt=None)
        result = self.plan(restore_receipt=None, retain_authenticated_repository=True)
        self.assertEqual(result['recovery_basis'], 'explicit_retained_repository_current_full_payload')
        self.assertTrue(result['retained_repository_must_be_retained'])
        with self.assertRaisesRegex(ValueError, 'boolean'):
            self.plan(retain_authenticated_repository=1)
        with patch.object(repo, 'verify_files', side_effect=ValueError('synthetic payload missing')):
            with self.assertRaisesRegex(ValueError, 'payload missing'):
                self.plan(restore_receipt=None, retain_authenticated_repository=True)

    def test_all_named_expansions_and_no_parent_sibling_nested_or_formal_archive(self):
        self.setup_pair()
        with patch.object(helper.psutil, 'process_iter', return_value=[]):
            for target in (self.working, self.root, self.working/'other', self.expansion/'state',
                           helper.PROJECT_ROOT/'archives'/'wechat-next'):
                with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'whitelist'):
                    helper.plan(target, self.repository, self.snapshot, restore_receipt=self.measurement,
                        _working_root=self.working)
        for name in sorted(helper.ALLOWED_NAMES - {self.expansion.name}):
            target = self.working/name
            rolling_delivery.restore(self.repository, self.snapshot, target)
            self.write_lifecycle(target)
            with patch.object(helper.psutil, 'process_iter', return_value=[]),\
                    patch.object(helper,'_process_identity',return_value=None):
                result = helper.plan(target, self.repository, self.snapshot,
                    retain_authenticated_repository=True, lifecycle_receipt=self.lifecycle,_working_root=self.working)
            self.assertEqual(result['target'], str(target.resolve()))

    def test_exact_raw_hash_corruption_missing_and_unknown_files_are_refused(self):
        self.setup_pair()
        target = self.expansion/'state/objects.sqlite'
        original = target.read_bytes()
        changed = bytearray(original); changed[100] ^= 1; target.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'hash differs'): self.plan()
        target.write_bytes(original)
        foreign = self.expansion/'unrecognized.original'; foreign.write_bytes(b'unique synthetic evidence')
        with self.assertRaisesRegex(ValueError, 'unexpected expansion'): self.plan()
        foreign.unlink(); target.unlink()
        with self.assertRaisesRegex(ValueError, 'unexpected expansion'): self.plan()

    def test_generated_markers_are_validated_not_unconditionally_ignored(self):
        self.setup_pair()
        for name in ('DELIVERY.partial.private.json', 'state/RESTORE.complete.private.json'):
            target = self.expansion/name; original = target.read_bytes()
            marker = json.loads(original); marker['snapshot_id'] = '0'*64
            self.write_json(target, marker)
            with self.subTest(marker=name), self.assertRaises(ValueError): self.plan()
            target.write_bytes(original)
        lock = self.expansion/'union/writer.lock'; lock.write_bytes(b'unrecognized user content')
        with self.assertRaisesRegex(ValueError, 'lock content'): self.plan()
        lock.write_bytes(b'0')
        self.assertTrue(self.plan()['plan_only'])

    def test_incomplete_or_unsafe_delivery_and_receipt_file_map_are_refused(self):
        self.setup_pair(); target = self.expansion/'DELIVERY.complete.private.json'
        for field, value in (('attachments_closed', False), ('capture_started', True),
                             ('source_reconnected', True), ('unexpected_field', 'unknown')):
            changed = copy.deepcopy(self.delivered); changed[field] = value
            self.write_json(target, changed)
            with self.subTest(field=field), self.assertRaises(ValueError): self.plan()
        changed = copy.deepcopy(self.delivered); changed['restored_files'].pop('state/objects.sqlite')
        self.write_json(target, changed)
        with self.assertRaisesRegex(ValueError, 'file map'): self.plan()

    def test_unknown_nested_generated_receipt_content_is_not_discarded(self):
        self.setup_pair(); target = self.expansion/'DELIVERY.complete.private.json'
        changed = copy.deepcopy(self.delivered)
        changed['state_restore']['verification']['unique_user_note'] = 'preserve synthetic added material'
        self.write_json(target, changed)
        with self.assertRaisesRegex(ValueError, 'unknown or unsafe state'): self.plan()
        changed = copy.deepcopy(self.delivered)
        changed['union_restore']['attachment_verification']['unique_user_note'] = 'preserve'
        self.write_json(target, changed)
        with self.assertRaisesRegex(ValueError, 'unknown or changed attachment'):
            self.plan(restore_receipt=None, retain_authenticated_repository=True)

    def test_measurement_requires_independent_success_same_snapshot_result_and_source_hashes(self):
        self.setup_pair()
        for field, value in (('partial', True), ('error_type', 'Interrupted'),
                             ('code_changed_during_run', True), ('source_hashes_after', {})):
            changed = copy.deepcopy(self.measured); changed[field] = value
            self.write_json(self.measurement, changed)
            with self.subTest(field=field), self.assertRaises(ValueError): self.plan()
        changed = copy.deepcopy(self.measured); changed['result']['snapshot_id'] = '0'*64
        self.write_json(self.measurement, changed)
        with self.assertRaises(ValueError): self.plan()
        with self.assertRaisesRegex(ValueError, 'independent'):
            self.plan(restore_receipt=self.expansion/'DELIVERY.complete.private.json')

    def test_snapshot_payload_corruption_refused_even_with_past_successful_restore(self):
        self.setup_pair()
        with repo.session(self.repository) as (db, _):
            db.execute("UPDATE block SET data=x'000000' WHERE kind='D'"); db.commit()
        with self.assertRaises(ValueError): self.plan()

    def test_manifest_without_accepted_generation_or_pin_is_not_a_retained_restore_point(self):
        self.setup_pair()
        with repo.session(self.repository) as (db, _):
            db.execute('DELETE FROM generation'); db.commit()
        with self.assertRaisesRegex(ValueError, 'accepted generation'): self.plan()

    def test_extra_empty_directory_is_not_a_blind_generated_allowance(self):
        self.setup_pair(); (self.expansion/'unknown-user-files').mkdir()
        with self.assertRaisesRegex(ValueError, 'unrecognized expansion directory'): self.plan()

    def test_repository_overlap_or_active_sidecar_and_protected_source_overlap_refused(self):
        self.setup_pair()
        original_repo = self.repository; self.repository = self.expansion
        with self.assertRaisesRegex(ValueError, 'overlaps'): self.plan()
        self.repository = original_repo
        sidecar = self.repository/(repo.DATABASE+'-journal'); sidecar.write_bytes(b'active synthetic journal')
        with self.assertRaisesRegex(ValueError, 'active/dirty'): self.plan()
        sidecar.unlink()
        original_manifest = repo.manifest
        def protected_manifest(*args):
            value = original_manifest(*args); value['context']['protected_roots'].append(str(self.working))
            return value
        with patch.object(repo, 'manifest', side_effect=protected_manifest):
            with self.assertRaisesRegex(ValueError, 'protected source'): self.plan()

    def test_inventory_identity_or_directory_drift_rejected_while_guards_are_held(self):
        self.setup_pair(); original = helper.inventory; counts = Counter()
        def changed_inventory(root):
            value = original(root); counts[Path(root)] += 1
            if Path(root) == self.expansion and counts[Path(root)] == 2:
                value['entries_sha256'] = '0'*64
            return value
        with patch.object(helper, 'inventory', side_effect=changed_inventory):
            with self.assertRaisesRegex(ValueError, 'drift'): self.plan()

    def test_guards_deny_writes_during_semantics_and_closure_failure_preserves_everything(self):
        self.setup_pair(); original = helper._verify_attachment_closure; blocked = []
        def guarded(root, value, receipt):
            with self.assertRaises(OSError):
                with (root/'state/objects.sqlite').open('r+b'):
                    self.fail('existing guarded input unexpectedly writable')
            blocked.append(True)
            return original(root, value, receipt)
        with patch.object(helper, '_verify_attachment_closure', side_effect=guarded):
            self.plan()
        self.assertTrue(blocked)
        before = self.all_hashes()
        with patch.object(helper, '_verify_attachment_closure', side_effect=ValueError('synthetic closure failed')):
            with self.assertRaisesRegex(ValueError, 'closure failed'): self.plan()
        self.assertEqual(before, self.all_hashes())

    def test_hardlink_and_junction_are_rejected_without_following(self):
        self.setup_pair(); link = self.expansion/'linked-file'
        os.link(self.expansion/'state/objects.sqlite', link)
        with self.assertRaisesRegex(ValueError, 'linked'): self.plan()
        link.unlink()
        import subprocess
        outside = self.root/'outside'; outside.mkdir(); junction = self.expansion/'linked-dir'
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(outside)], capture_output=True)
        if result.returncode: self.skipTest('junction creation unavailable')
        try:
            with self.assertRaisesRegex(ValueError, 'linked'): self.plan()
        finally:
            junction.rmdir()

    def test_process_dependencies_unknown_access_denied_and_system_exceptions(self):
        self.setup_pair()
        target_process = SimpleNamespace(pid=2147483600, info=dict(name='python.exe',
            ppid=0,exe=str(helper.PROJECT_ROOT/'synthetic/python.exe')),
            cmdline=Mock(return_value=['python',str(self.expansion)]),cwd=Mock(return_value='C:/synthetic'))
        denied = SimpleNamespace(pid=2147483601, info=dict(name='CaptureNextCore.exe',
            ppid=helper._DENIED,exe=helper._DENIED))
        for candidate in (target_process, denied):
            with patch.object(helper.psutil, 'process_iter', return_value=[candidate]):
                with self.assertRaises(ValueError): helper._dependencies(self.expansion)
        system = SimpleNamespace(pid=2147483602, info=dict(name='lsass.exe',
            ppid=helper._DENIED,exe=helper._DENIED))
        with patch.object(helper.psutil, 'process_iter', return_value=[system]):
            value = helper._dependencies(self.expansion)
        self.assertEqual(value['uninspectable_unrelated_or_unclassified_pids'], [system.pid])
        unrelated=SimpleNamespace(pid=2147483603,info=dict(name='unrelated.exe',
            ppid=helper._DENIED,exe=helper._DENIED))
        with patch.object(helper.psutil,'process_iter',return_value=[unrelated]):
            value=helper._dependencies(self.expansion)
        self.assertEqual(value['uninspectable_unrelated_or_unclassified_pids'],[unrelated.pid])
        self.assertFalse(value['global_dependency_absence_proven'])

    def test_private_cli_plan_is_fresh_and_never_writes_into_expansion(self):
        self.setup_pair(); out = self.working/'cleanup.private.json'
        arguments = ['--root', str(self.expansion), '--repository', str(self.repository),
            '--snapshot', self.snapshot, '--restore-receipt', str(self.measurement),
            '--lifecycle-receipt',str(self.lifecycle),'--out', str(out)]
        with patch.object(helper, 'WORKING_ROOT', self.working), \
                patch.object(helper,'_process_identity',return_value=None),\
                patch.object(helper.psutil, 'process_iter', return_value=[]):
            helper.main(arguments)
            with self.assertRaisesRegex(ValueError, 'fresh'): helper.main(arguments)
        self.assertFalse(json.loads(out.read_text(encoding='utf-8'))['deletion_executed'])
        self.assertTrue(self.expansion.is_dir())

    def test_lifecycle_evidence_is_required_and_final_census_not_initial_is_reported(self):
        self.setup_pair()
        with self.assertRaisesRegex(ValueError,'lifecycle receipt'):self.plan(lifecycle_receipt=None)
        with patch.object(helper,'_dependencies',side_effect=[dict(marker='initial'),dict(marker='final')]):
            value=self.plan()
        self.assertEqual(value['initial_process_dependencies']['marker'],'initial')
        self.assertEqual(value['process_dependencies']['marker'],'final')
        self.assertEqual(value['target_access_probe']['process_dependencies']['marker'],'final')
        self.assertTrue(value['task_lifecycle_verified']);self.assertFalse(value['global_dependency_absence_proven'])

    def test_semantic_release_gap_same_size_same_mtime_change_fails_final_handle_hash(self):
        self.setup_pair();original_probe=helper._exclusive_probe
        target=self.expansion/'state/config.private.json';original=target.read_bytes()
        def changed_after_semantics(*args,**kwargs):
            info=target.stat();target.write_bytes(b'x'*len(original))
            os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
            return original_probe(*args,**kwargs)
        with patch.object(helper,'_exclusive_probe',side_effect=changed_after_semantics):
            with self.assertRaisesRegex(ValueError,'hash differs'):self.plan()
        target.write_bytes(original)

    def test_legacy_missing_only_identity_summary_requires_real_readonly_zero_index_proof(self):
        self.setup_pair(legacy_identity_summary=True)
        from wechat_capture_next.viewer_identity import verify as verify_identity
        before=self.all_hashes()
        with patch('wechat_capture_next.viewer_identity.verify',wraps=verify_identity) as identity:
            result=self.plan()
        identity.assert_called_once()
        self.assertTrue(identity.call_args.args[0].readonly)
        proof=result['attachment_closure']['legacy_identity_summary_compatibility']
        self.assertTrue(proof['applied']);self.assertTrue(proof['other_integrity_fields_exactly_equal'])
        self.assertEqual(proof['current_readonly_identity_verification'],dict(status='not_indexed',rows_verified=0))
        self.assertFalse(proof['fts_reexecuted']);self.assertEqual(before,self.all_hashes())

    def test_legacy_identity_summary_rejects_current_unknown_nonzero_or_extra_fields(self):
        self.setup_pair(legacy_identity_summary=True)
        for current in (dict(status='verified',rows_verified=0),dict(status='not_indexed',rows_verified=1),
                dict(status='not_indexed',rows_verified=False),dict(status='not_indexed',rows_verified=0,unknown=True)):
            with self.subTest(current=current),patch('wechat_capture_next.viewer_identity.verify',return_value=current):
                with self.assertRaisesRegex(ValueError,'current exact not_indexed'):self.plan()

    def test_legacy_identity_summary_rejects_receipt_other_changes_and_orphan_tables(self):
        self.setup_pair(legacy_identity_summary=True)
        marker=self.expansion/'DELIVERY.complete.private.json';original=marker.read_bytes()
        for value in (dict(status='not_indexed',rows_verified=1),dict(status='not_indexed',rows_verified=0,unknown=True)):
            changed=copy.deepcopy(self.delivered);changed['union_restore']['integrity']['identities']=value
            self.write_json(marker,changed)
            with self.assertRaisesRegex(ValueError,'integrity receipt differs'):self.plan()
        changed=copy.deepcopy(self.delivered);changed['union_restore']['integrity']['unknown']=True
        self.write_json(marker,changed)
        with self.assertRaisesRegex(ValueError,'integrity receipt differs'):self.plan()
        changed=copy.deepcopy(self.delivered)
        changed['union_restore']['integrity']['raw_observations_verified']=float(changed['union_restore']['integrity']['raw_observations_verified'])
        self.write_json(marker,changed)
        with self.assertRaisesRegex(ValueError,'integrity receipt differs'):self.plan()
        marker.write_bytes(original)
        from wechat_capture_next.viewer_identity import verify as verify_identity
        def orphan(archive):
            class Cursor:
                def fetchone(self):return (1,)
            class Database:
                def __getattr__(self,name):return getattr(real_db,name)
                def execute(self,*args,**kwargs):
                    if 'sqlite_master WHERE name COLLATE NOCASE IN' in args[0]:return Cursor()
                    return real_db.execute(*args,**kwargs)
            real_db=archive._db
            result=verify_identity(archive)
            archive._db=Database()
            return result
        # No schema write is used even for this failure injection.
        with patch('wechat_capture_next.viewer_identity.verify',side_effect=orphan):
            with self.assertRaisesRegex(ValueError,'orphan identity'):self.plan()

    def test_exact_eight_field_legacy_context_passes_only_real_readonly_unindexed_media(self):
        self.setup_pair(legacy_identity_summary=True,legacy_media_binding=True)
        with repo.session(self.repository,readonly=True) as (database,owner):
            context=repo.manifest(database,self.snapshot,owner)['context']
        self.assertEqual(set(context),set(helper.REQUIRED_CONTEXT_FIELDS))
        from wechat_capture_next.viewer_media import verify as verify_media
        before=self.all_hashes()
        with patch('wechat_capture_next.viewer_media.verify',wraps=verify_media) as media:
            result=self.plan()
        media.assert_called_once();self.assertTrue(media.call_args.args[0].readonly)
        proof=result['attachment_closure']['legacy_media_binding_compatibility']
        self.assertTrue(proof['applied']);self.assertTrue(proof['no_media_schema_markers_or_known_objects'])
        self.assertEqual(proof['current_readonly_media_verification'],dict(status='not_indexed',rows_verified=0))
        self.assertFalse(result['attachment_closure']['native_media_verified'])
        self.assertEqual(before,self.all_hashes())

    def test_missing_media_binding_rejects_nonzero_unknown_bool_float_or_extra_current_summary(self):
        self.setup_pair(legacy_identity_summary=True,legacy_media_binding=True)
        for current in (dict(status='verified',rows_verified=0),dict(status='not_indexed',rows_verified=1),
                dict(status='not_indexed',rows_verified=False),dict(status='not_indexed',rows_verified=0.0),
                dict(status='not_indexed',rows_verified=0,unknown=True)):
            with self.subTest(current=current),patch('wechat_capture_next.viewer_media.verify',return_value=current):
                with self.assertRaisesRegex(ValueError,'current exact not_indexed'):self.plan()

    def test_missing_media_binding_rejects_receipt_summary_change_and_orphan_schema(self):
        self.setup_pair(legacy_identity_summary=True,legacy_media_binding=True)
        marker=self.expansion/'DELIVERY.complete.private.json';original=marker.read_bytes()
        for summary in (dict(status='verified',rows_verified=0),dict(status='not_indexed',rows_verified=1),
                dict(status='not_indexed',rows_verified=False),dict(status='not_indexed',rows_verified=0,extra=True)):
            changed=copy.deepcopy(self.delivered);changed['union_restore']['media_verification']=summary
            self.write_json(marker,changed)
            with self.subTest(summary=summary),self.assertRaisesRegex(ValueError,'legacy media receipt'):self.plan()
        marker.write_bytes(original)
        with patch.object(helper,'_has_media_schema',return_value=True):
            with self.assertRaisesRegex(ValueError,'schema markers or unknown/orphan'):self.plan()

    def test_maintenance_module_contains_no_delete_or_move_implementation(self):
        tree = ast.parse(Path(helper.__file__).read_text(encoding='utf-8'))
        forbidden = {'unlink', 'rmdir', 'rmtree', 'remove', 'rename', 'move', 'DeleteFileW', 'MoveFileW',
            'SetFileInformationByHandle','chmod','kill','terminate','TerminateProcess','AdjustTokenPrivileges'}
        calls = {node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & forbidden)
        self.assertNotIn('FILE_FLAG_DELETE_ON_CLOSE',Path(helper.__file__).read_text(encoding='utf-8'))
        self.assertNotIn(0x04000000,{node.value for node in ast.walk(tree) if isinstance(node,ast.Constant) and type(node.value) is int})


class IdentitySchemaCaseTests(unittest.TestCase):
    def test_uppercase_and_mixed_case_orphan_tables_are_rejected_by_real_sqlite_query(self):
        for name in ('NEXT_VIEWER_IDENTITY','Next_Viewer_Aux_Snapshot','nExT_vIeWeR_aUx_RoW'):
            with self.subTest(name=name),sqlite3.connect(':memory:') as database:
                self.assertFalse(helper._has_identity_schema_objects(database))
                database.execute('CREATE TABLE '+name+'(value)')
                self.assertEqual(database.execute('SELECT count(*) FROM '+name.lower()).fetchone()[0],0)
                self.assertTrue(helper._has_identity_schema_objects(database))

    def test_mixed_case_identity_index_or_view_is_unknown_schema_not_an_ignored_table(self):
        with sqlite3.connect(':memory:') as database:
            database.execute('CREATE TABLE unrelated_original(value)')
            database.execute('CREATE INDEX NeXt_ViEwEr_IdEnTiTy ON unrelated_original(value)')
            self.assertTrue(helper._has_identity_schema_objects(database))
        with sqlite3.connect(':memory:') as database:
            database.execute('CREATE VIEW NeXt_ViEwEr_AuX_rOw AS SELECT 1 AS value')
            self.assertTrue(helper._has_identity_schema_objects(database))

    def test_only_exact_known_identity_names_match_not_unrelated_prefixes(self):
        with sqlite3.connect(':memory:') as database:
            database.execute('CREATE TABLE NEXT_VIEWER_IDENTITY_EXTRA(value)')
            self.assertFalse(helper._has_identity_schema_objects(database))


class MediaSchemaCaseTests(unittest.TestCase):
    def test_any_known_media_table_view_or_index_is_found_case_insensitively(self):
        for name in ('NEXT_MEDIA_SNAPSHOT','Next_Media_Row','NeXt_MeDiA_VoIcE','NEXT_MEDIA_VOICE_KEY'):
            with self.subTest(name=name),sqlite3.connect(':memory:') as database:
                database.execute('CREATE TABLE archive_meta(key,value)')
                database.execute('CREATE TABLE '+name+'(value)')
                self.assertEqual(database.execute('SELECT count(*) FROM '+name.lower()).fetchone()[0],0)
                self.assertTrue(helper._has_media_schema(database))
        with sqlite3.connect(':memory:') as database:
            database.execute('CREATE TABLE archive_meta(key,value)')
            database.execute('CREATE INDEX NeXt_MeDiA_VoIcE_LoOkUp ON archive_meta(value)')
            self.assertTrue(helper._has_media_schema(database))
        with sqlite3.connect(':memory:') as database:
            database.execute('CREATE TABLE archive_meta(key,value)')
            database.execute('CREATE VIEW nExT_mEdIa_VoIcE AS SELECT 1')
            self.assertTrue(helper._has_media_schema(database))

    def test_media_schema_cas_owner_or_unknown_prefix_marker_is_never_absence(self):
        for key in ('next_viewer_media_schema','NEXT_VIEWER_MEDIA_CAS','NeXt_ViEwEr_MeDiA_OwNeR','next_viewer_media_future'):
            with self.subTest(key=key),sqlite3.connect(':memory:') as database:
                database.execute('CREATE TABLE archive_meta(key,value)')
                self.assertFalse(helper._has_media_schema(database))
                database.execute('INSERT INTO archive_meta VALUES(?,?)',(key,'unknown-or-even-empty'))
                self.assertTrue(helper._has_media_schema(database))

    def test_existing_media_binding_remains_exact_canonical_and_missing_is_not_a_blanket_default(self):
        expected=dict(status='not_indexed',rows_verified=0)
        self.assertEqual(helper._expected_media_binding({},expected),expected)
        for context,receipt in ((dict(media_binding=expected),dict(status='not_indexed',rows_verified=False)),
                (dict(media_binding=None),expected),({},dict(status='not_indexed',rows_verified=0,extra=True))):
            with self.subTest(context=context,receipt=receipt),self.assertRaises(ValueError):
                helper._expected_media_binding(context,receipt)


class LifecycleTests(unittest.TestCase):
    def receipt(self,created=100.0,exited=None):
        return dict(schema=helper.LIFECYCLE_SCHEMA,target=str(Path.cwd()),coverage_complete=True,
            processes=[dict(role='owned-child',pid=1234567,create_time=created,exit_receipt=exited)])

    def test_absent_pid_is_confirmed_exited_even_without_creation_time(self):
        with patch.object(helper,'_process_identity',return_value=None):
            value=helper._task_lifecycle(self.receipt(created=None),Path.cwd())
        self.assertEqual(value['processes'][0]['status'],'pid_absent_now')
        self.assertFalse(value['global_dependency_absence_proven'])

    def test_persistent_exit_receipt_is_preserved_but_current_absence_is_still_checked(self):
        exited=dict(pid=1234567,create_time=100.0,exited=True,exit_code=0,observed_unix=time.time())
        with patch.object(helper,'_process_identity',return_value=None) as current:
            value=helper._task_lifecycle(self.receipt(exited=exited),Path.cwd())
        current.assert_called_once_with(1234567)
        self.assertEqual(value['processes'][0]['persistent_exit_receipt'],exited)

    def test_os_process_identity_absence_or_access_denied_are_not_confused(self):
        with patch.object(helper.psutil,'Process',side_effect=helper.psutil.NoSuchProcess(1234567)):
            self.assertIsNone(helper._process_identity(1234567))
        with patch.object(helper.psutil,'Process',side_effect=helper.psutil.AccessDenied(1234567)):
            with self.assertRaisesRegex(ValueError,'lifecycle unavailable'):helper._process_identity(1234567)

    def test_live_pid_or_missing_creation_identity_is_closed_even_with_exit_receipt(self):
        exited=dict(pid=1234567,create_time=100.0,exited=True,exit_code=0,observed_unix=time.time())
        with patch.object(helper,'_process_identity',return_value=100.0):
            for receipt in (self.receipt(),self.receipt(created=None),self.receipt(exited=exited)):
                with self.subTest(receipt=receipt),self.assertRaises(ValueError):
                    helper._task_lifecycle(receipt,Path.cwd())

    def test_pid_reuse_identifies_original_instance_not_current_unrelated_instance(self):
        with patch.object(helper,'_process_identity',return_value=200.0):
            value=helper._task_lifecycle(self.receipt(),Path.cwd())
        self.assertEqual(value['processes'][0]['status'],'original_exited_pid_reused')
        with patch.object(helper,'_process_identity',return_value=99.0):
            with self.assertRaises(ValueError):helper._task_lifecycle(self.receipt(),Path.cwd())

    def test_missing_unknown_or_denied_task_lifecycle_is_not_success(self):
        with patch.object(helper,'_process_identity',side_effect=ValueError('known task inaccessible')):
            with self.assertRaises(ValueError):helper._task_lifecycle(self.receipt(),Path.cwd())
        receipt=self.receipt();receipt['coverage_complete']=False
        with self.assertRaises(ValueError):helper._task_lifecycle(receipt,Path.cwd())
        receipt=self.receipt();receipt['processes']=[]
        with self.assertRaises(ValueError):helper._task_lifecycle(receipt,Path.cwd())


class TaskCensusScopeTests(unittest.TestCase):
    def process(self,pid,*,name='unclassified.exe',exe='C:/Outside/unclassified.exe',ppid=0,command=None):
        return SimpleNamespace(pid=pid,info=dict(name=name,exe=exe,ppid=ppid),create_time=Mock(return_value=100.0),
            cmdline=Mock(return_value=command or ['opaque']),cwd=Mock(return_value='C:/Outside'))

    def test_third_party_command_and_cwd_are_never_requested_even_when_readable(self):
        root=Path.cwd()/'synthetic-target'
        outside=self.process(2147483400,command=['third-party',str(root)])
        inaccessible=self.process(2147483401,exe=helper._DENIED)
        for process in (outside,inaccessible):
            process.cmdline.side_effect=AssertionError('third-party command privacy')
            process.cwd.side_effect=AssertionError('third-party cwd privacy')
        with patch.object(helper.psutil,'process_iter',return_value=[outside,inaccessible]) as census:
            result=helper._dependencies(root)
        census.assert_called_once_with(['pid','name','exe','ppid'],ad_value=helper._DENIED)
        for process in (outside,inaccessible):process.cmdline.assert_not_called();process.cwd.assert_not_called()
        self.assertEqual(set(result['unclassified_process_pids']),{outside.pid,inaccessible.pid})
        self.assertFalse(result['global_dependency_absence_proven'])
        self.assertFalse(result['unclassified_command_or_cwd_requested'])

    def test_project_executable_descendant_declared_pid_and_task_name_are_selected(self):
        root=Path.cwd()/'synthetic-target'
        project=self.process(2147483402,exe=str(helper.PROJECT_ROOT/'runtime/python.exe'))
        child=self.process(2147483403,ppid=project.pid)
        declared=self.process(2147483404)
        named=self.process(2147483405,name='CaptureNextCore.exe')
        with patch.object(helper.psutil,'process_iter',return_value=[child,project,declared,named]):
            result=helper._dependencies(root,task_pids={declared.pid})
        self.assertEqual(set(result['task_text_inspected_pids']),{p.pid for p in (project,child,declared,named)})
        for process in (project,child,declared,named):process.cmdline.assert_called_once();process.cwd.assert_called_once()
        declared.cmdline.return_value=['python',str(root)]
        with patch.object(helper.psutil,'process_iter',return_value=[declared]):
            with self.assertRaisesRegex(ValueError,'still references'):helper._dependencies(root,task_pids={declared.pid})

    def test_pid_or_ppid_reuse_does_not_select_unrelated_command_contents(self):
        root=Path.cwd()/'synthetic-target'
        project=self.process(2147483406,exe=str(helper.PROJECT_ROOT/'runtime/python.exe'))
        project.create_time.return_value=200.0
        old_child=self.process(2147483407,ppid=project.pid)
        reused=self.process(2147483408);reused.create_time.return_value=200.0
        for process in (old_child,reused):
            process.cmdline.side_effect=AssertionError('reused identity command privacy')
            process.cwd.side_effect=AssertionError('reused identity cwd privacy')
        with patch.object(helper.psutil,'process_iter',return_value=[old_child,project,reused]):
            result=helper._dependencies(root,task_pids={reused.pid:100.0})
        self.assertEqual(result['task_text_inspected_pids'],[project.pid])
        for process in (old_child,reused):process.cmdline.assert_not_called();process.cwd.assert_not_called()


@unittest.skipUnless(os.name=='nt','native Windows exclusive access probe')
class ExclusiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'micro';self.root.mkdir()
        (self.root/'empty').mkdir();(self.root/'nested').mkdir()
        self.first=self.root/'one.bin';self.first.write_bytes(b'first original')
        self.second=self.root/'nested/two.bin';self.second.write_bytes(b'second original')
        self.evidence=helper.inventory(self.root)
        self.hashes={row['relative']:digest_file(self.root/row['relative']) for row in self.evidence['files']}
        self.dirs=helper._directory_identities(self.root,self.evidence)

    def probe(self,final_checks=None):
        return helper._exclusive_probe(self.root,self.evidence,self.hashes,self.dirs,final_checks or (lambda:dict(
            process_dependencies=dict(scope='synthetic'),task_lifecycle=dict(task_lifecycle_verified=True))))

    @contextmanager
    def handle(self,path,access=0x80000000,share=7,directory=False):
        native=helper._WindowsProbe()
        handle=native.kernel.CreateFileW(str(path),access,share,None,3,0x02000000 if directory else 0,None)
        if handle==helper.ctypes.c_void_p(-1).value:raise helper.ctypes.WinError(helper.ctypes.get_last_error())
        try:yield handle
        finally:native.close(handle)

    def test_micro_tree_passes_through_native_directory_enumeration_and_handle_sha(self):
        value=self.probe()
        self.assertTrue(value['target_access_probe_passed']);self.assertTrue(value['all_owned_probe_handles_closed'])
        self.assertEqual(value['sha256'],self.hashes);self.assertEqual(value['directories_including_root'],3)
        self.assertFalse(value['global_dependency_absence_proven'])

    def test_ordinary_reader_and_writer_and_share_delete_reader_each_refuse(self):
        for mode in ('rb','r+b'):
            with self.subTest(mode=mode),self.second.open(mode):
                with self.assertRaises(OSError):self.probe()
            self.assertTrue(self.probe()['target_access_probe_passed'])
        with self.handle(self.second,share=7):
            with self.assertRaises(OSError):self.probe()
        self.assertTrue(self.probe()['target_access_probe_passed'])

    def test_directory_handle_and_live_child_cwd_are_refused(self):
        with self.handle(self.root/'nested',directory=True):
            with self.assertRaises(OSError):self.probe()
        child=subprocess.Popen([sys.executable,'-c',"import sys;print('ready',flush=True);sys.stdin.buffer.read(1)"],
            cwd=self.root/'nested',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            self.assertEqual(child.stdout.readline(),b'ready\r\n')
            with self.assertRaises(OSError):self.probe()
        finally:
            child.communicate(b'x',timeout=10)
        self.assertTrue(self.probe()['target_access_probe_passed'])

    def test_exception_releases_every_own_handle_and_preserves_all_bytes(self):
        native=helper._WindowsProbe();opened=[];closed=[]
        original_open=native.open;original_close=native.close
        def opening(*args,**kwargs):
            handle=original_open(*args,**kwargs);opened.append(handle);return handle
        def closing(handle):closed.append(handle);return original_close(handle)
        with patch.object(helper,'_WindowsProbe',return_value=native),\
             patch.object(native,'open',side_effect=opening),patch.object(native,'close',side_effect=closing),\
             patch.object(native,'sha256',side_effect=ValueError('synthetic failure')):
            with self.assertRaisesRegex(ValueError,'synthetic failure'):self.probe()
        self.assertEqual(set(opened),set(closed));self.assertEqual(len(opened),len(closed))
        self.assertEqual(self.hashes,{row['relative']:digest_file(self.root/row['relative']) for row in self.evidence['files']})
        self.assertTrue(self.probe()['target_access_probe_passed'])

    def test_same_size_same_mtime_tamper_is_not_metadata_success(self):
        before=self.first.stat();original=self.first.read_bytes()
        self.first.write_bytes(b'x'*len(original));os.utime(self.first,ns=(before.st_atime_ns,before.st_mtime_ns))
        self.assertEqual(helper.inventory(self.root)['entries_sha256'],self.evidence['entries_sha256'])
        with self.assertRaisesRegex(ValueError,'hash differs'):self.probe()
        self.first.write_bytes(original)  # proves no leaked exclusive handle

    def test_new_path_and_hardlink_and_replaced_identity_each_fail(self):
        new=self.root/'new.bin';new.write_bytes(b'new')
        with self.assertRaisesRegex(ValueError,'inventory drift'):self.probe()
        new.unlink()
        linked=Path(self.temp.name)/'outside-hardlink';os.link(self.first,linked)
        with self.assertRaisesRegex(ValueError,'inventory/identity'):self.probe()
        linked.unlink()
        old=self.first.read_bytes();self.first.unlink();self.first.write_bytes(old)
        with self.assertRaisesRegex(ValueError,'inventory/identity'):self.probe()

    def test_new_junction_is_not_followed(self):
        outside=Path(self.temp.name)/'outside';outside.mkdir()
        replaced=self.root/'empty';replaced.rmdir()
        result=subprocess.run(['cmd','/c','mklink','/J',str(replaced),str(outside)],capture_output=True)
        if result.returncode:self.skipTest('junction unavailable')
        try:
            with self.assertRaisesRegex(ValueError,'reparse'):self.probe()
        finally:replaced.rmdir()

    def test_unique_file_created_during_final_checks_cannot_receive_pass(self):
        late=self.root/'late-unique.txt'
        def checks():
            late.write_bytes(b'unique material created after the preceding enumeration')
            return {}
        with self.assertRaisesRegex(ValueError,'inventory drift'):self.probe(final_checks=checks)
        self.assertEqual(late.read_bytes(),b'unique material created after the preceding enumeration')

    def test_unique_directory_created_during_final_checks_cannot_receive_pass(self):
        late=self.root/'nested/late-unique-directory'
        def checks():late.mkdir();return {}
        with self.assertRaisesRegex(ValueError,'inventory drift'):self.probe(final_checks=checks)
        self.assertTrue(late.is_dir())


if __name__ == '__main__':
    unittest.main()
