from contextlib import redirect_stdout,redirect_stderr,closing
import io
import json
from pathlib import Path
import sqlite3
import time
import unittest
from unittest.mock import patch
from wechat_capture_next.tests import test_union_delivery as fixtures
from wechat_capture_next import rolling_delivery,product_host
from wechat_capture_next.recovery_core import RecoveryCore,active_binding,mark_binding_initialized
from wechat_capture_next.product_settings import atomic_json
from wechat_capture_next.service import CaptureService
from wechat_capture_next.product import ProductCore
from wechat_capture_next.backup import SECRETS
from wechat_capture_next.offline_view import OfflineView
from wechat_capture_next.state_guard import writer_lock
from wechat_capture_v2.common import digest_file


class RecoveryTests(unittest.TestCase):
    setUp=fixtures.UnionDeliveryTests.setUp
    tearDown=fixtures.UnionDeliveryTests.tearDown
    pages=fixtures.UnionDeliveryTests.pages
    publish=fixtures.UnionDeliveryTests.publish
    init_service=fixtures.UnionDeliveryTests.init_service
    prepared=fixtures.UnionDeliveryTests.prepared
    take_source_offline=fixtures.UnionDeliveryTests.take_source_offline
    def setup_copy(self,include_secrets=False,key_transform=None):
        self.prepared();self.paired=self.root/'pair'
        if key_transform:
            path=self.state/SECRETS;payload=json.loads(path.read_text(encoding='utf-8'))
            path.write_text(json.dumps(key_transform(payload)),encoding='utf-8')
        backup=rolling_delivery.backup(self.state,self.formal,self.paired,include_secrets=include_secrets)
        self.restored=self.root/'restored';rolling_delivery.restore(self.paired,backup['snapshot_id'],self.restored)
        self.base=self.root/'appbase'
    def core(self):
        core=RecoveryCore(self.base,state=self.state,union_root=self.formal,repository_root=self.state_repo,
            union_repository=self.union_repo,paired_repository=self.paired)
        self.addCleanup(core.close);return core
    def wait(self,core,job,expected='completed'):
        end=time.monotonic()+10
        while time.monotonic()<end:
            row=next(j for j in core.jobs_snapshot()['jobs'] if j['id']==job['id'])
            if row['status'] not in ('queued','running'):
                self.assertEqual(row['status'],expected,row);return row
            time.sleep(.01)
        self.fail('recovery job stuck')
    def test_no_key_source_start_and_readonly_view(self):
        self.setup_copy();self.take_source_offline()
        before={p:digest_file(p) for p in self.restored.rglob('*') if p.is_file()}
        with patch.object(CaptureService,'__init__',side_effect=AssertionError('live constructor forbidden')):
            core=self.core()
            self.wait(core,core.submit(dict(action='open_restored',path=str(self.restored))))
            rows=product_host.product_read(core,'/api/union-messages',dict(view=['restored']))['rows']
            self.assertEqual(len(rows),40)
            with self.assertRaises(ValueError):core.submit(dict(action='start_watch'))
            with self.assertRaises(ValueError):product_host.product_read(core,'/api/union-messages',{})
            self.wait(core,core.submit(dict(action='close_restored')))
        self.assertEqual(before,{p:digest_file(p) for p in self.restored.rglob('*') if p.is_file()})
    def test_safe_binding_does_not_overwrite_original_and_resumed_state_can_mutate(self):
        self.setup_copy(include_secrets=True);core=self.core();before=digest_file(self.state/'catalog.sqlite')
        with writer_lock(self.state):
            self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),confirm='USE_VERIFIED_COPY')),expected='failed')
        self.assertFalse((self.base/'active-binding.private.json').exists())
        self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),confirm='USE_VERIFIED_COPY')))
        self.assertEqual(before,digest_file(self.state/'catalog.sqlite'))
        value=active_binding(self.base);self.assertTrue(value['start_paused'])
        marker=self.base/'active-binding.private.json';binding=json.loads(marker.read_text(encoding='utf-8'))
        binding['capture_paused']=False;atomic_json(marker,binding)
        with closing(sqlite3.connect(self.restored/'state/catalog.sqlite')) as db:
            db.execute("INSERT INTO meta VALUES('synthetic-after-promotion','changed')");db.commit()
        self.assertFalse(active_binding(self.base)['start_paused'])
    def test_host_offline_and_broken_state_modes_do_not_require_capture_constructor(self):
        self.setup_copy();self.take_source_offline()
        for args in (['--root',str(self.root),'--offline',str(self.restored)],['--root',str(self.root),'--recovery'],['--root',str(self.root)]):
            out=io.StringIO()
            with patch.object(CaptureService,'__init__',side_effect=AssertionError('no live constructor')),\
                 patch('sys.stdin',io.StringIO('quit\n')),redirect_stdout(out),redirect_stderr(io.StringIO()):
                self.assertEqual(product_host.main(args),0)
            self.assertEqual(json.loads(out.getvalue())['mode'],'recovery')
    def test_competing_recovery_cannot_rewrite_owned_journal(self):
        self.setup_copy();core=self.core();core.close()
        path=core.output_root/'operations.private.json'
        with writer_lock(core.output_root):
            original=path.read_bytes() if path.exists() else None
            with self.assertRaises(RuntimeError):self.core()
            self.assertEqual(original,path.read_bytes() if path.exists() else None)
    def test_busy_active_recovered_copy_blocks_second_takeover(self):
        self.setup_copy(include_secrets=True);core=self.core()
        self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),confirm='USE_VERIFIED_COPY')))
        marker=self.base/'active-binding.private.json';binding=json.loads(marker.read_text(encoding='utf-8'))
        binding['capture_paused']=False;atomic_json(marker,binding);before=marker.read_bytes()
        second=self.root/'second-restored';snapshot=binding['snapshot_id']
        rolling_delivery.restore(self.paired,snapshot,second)
        with writer_lock(self.restored/'state'):
            self.wait(core,core.submit(dict(action='promote_restore',path=str(second),confirm='USE_VERIFIED_COPY')),expected='failed')
        self.assertEqual(before,marker.read_bytes())

    def test_keyless_promotion_is_actionable_warning_without_binding_or_mutation(self):
        self.setup_copy();core=self.core()
        before={p:digest_file(p) for root in (self.restored,self.state,self.formal)
            for p in root.rglob('*') if p.is_file()}
        job=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')
        result=job['result']
        self.assertEqual(result['reason'],'receipt_key_material_missing')
        self.assertFalse(result['binding_prepared']);self.assertFalse(result['capture_started'])
        self.assertIn('include_secrets=true',result['next_step'])
        self.assertFalse((self.base/'active-binding.private.json').exists())
        self.assertEqual(before,{p:digest_file(p) for root in (self.restored,self.state,self.formal)
            for p in root.rglob('*') if p.is_file()})
        # The warning remains actionable after a recovery UI restart.
        core.close();core=self.core()
        row=next(r for r in core.jobs_snapshot()['jobs'] if r['id']==job['id'])
        self.assertEqual(row['status'],'warning');self.assertEqual(row['result'],result)
        self.assertFalse(core.control_snapshot()['product']['takeover']['external_key_import_supported'])
        self.wait(core,core.submit(dict(action='open_restored',path=str(self.restored))))

    def test_unreceipted_key_file_cannot_turn_keyless_copy_into_takeover(self):
        self.setup_copy();target=self.restored/'state'/SECRETS
        target.parent.mkdir();target.write_bytes((self.state/SECRETS).read_bytes())
        core=self.core()
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'receipt_key_material_missing')
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_malformed_verified_key_material_blocks_takeover(self):
        self.setup_copy(include_secrets=True,key_transform=lambda p:dict(p,databases=[dict(
            p['databases'][0],raw_encryption_key_hex='invalid')]))
        core=self.core()
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'key_material_or_binding_invalid')
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_partial_captured_key_inventory_blocks_takeover(self):
        self.setup_copy(include_secrets=True,key_transform=lambda p:dict(p,databases=[dict(
            p['databases'][0],relative_path='another.db')]))
        core=self.core()
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'captured_shard_keys_incomplete')
        self.assertEqual(result['missing_keys'],1)
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_empty_verified_material_blocks_takeover(self):
        self.setup_copy(include_secrets=True,key_transform=lambda p:dict(p,databases=[]))
        core=self.core()
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'verified_key_material_empty')
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_normalized_duplicate_key_material_is_rejected(self):
        self.setup_copy(include_secrets=True,key_transform=lambda p:dict(p,databases=p['databases']*2))
        core=self.core()
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'key_material_or_binding_invalid')
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_well_formed_wrong_key_is_not_accepted_as_capture_material(self):
        self.setup_copy(include_secrets=True,key_transform=lambda p:dict(p,databases=[dict(
            p['databases'][0],raw_encryption_key_hex='00'*32)]))
        core=self.core()
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'current_source_authentication_unavailable')
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_source_missing_blocks_takeover_but_not_secret_backed_offline_view(self):
        self.setup_copy(include_secrets=True);self.take_source_offline();core=self.core()
        self.wait(core,core.submit(dict(action='open_restored',path=str(self.restored))))
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'current_source_authentication_unavailable')
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_current_new_shard_without_key_blocks_takeover(self):
        self.setup_copy(include_secrets=True)
        self.source.with_name('new-shard.db').write_bytes(self.source.read_bytes())
        core=self.core()
        result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
            confirm='USE_VERIFIED_COPY')),expected='warning')['result']
        self.assertEqual(result['reason'],'current_source_keys_incomplete')
        self.assertFalse((self.base/'active-binding.private.json').exists())

    def test_secret_backed_promotion_and_paused_restart_never_capture(self):
        self.setup_copy(include_secrets=True);core=self.core()
        before={p:digest_file(p) for root in (self.state,self.formal) for p in root.rglob('*') if p.is_file()}
        with patch.object(CaptureService,'capture',side_effect=AssertionError('automatic capture forbidden')):
            result=self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),
                confirm='USE_VERIFIED_COPY')))['result']
            self.assertTrue(result['live_source_authenticated']);self.assertTrue(result['binding_prepared'])
            self.assertEqual(result['verification_scope'],'current_source_first_page_hmac_only')
            self.assertFalse(result['capture_started']);self.assertFalse(result['login_started'])
            binding=active_binding(self.base)
            core.close()
            for _ in range(2):
                restarted=ProductCore(**binding,repository_root=self.state_repo,union_repository=self.union_repo,
                    paired_repository=self.paired)
                try:
                    self.assertFalse(restarted.control_snapshot()['watching'])
                    self.assertFalse(restarted.settings['auto_capture'])
                finally:restarted.close()
                binding=active_binding(self.base)
                self.assertTrue(binding['start_paused'])
        self.assertEqual(before,{p:digest_file(p) for root in (self.state,self.formal) for p in root.rglob('*') if p.is_file()})

    def test_legacy_keyless_paused_binding_is_rejected_on_startup(self):
        self.setup_copy();core=self.core()
        reader=OfflineView(self.restored)
        try:core._publish_binding(reader,'legacy-synthetic')
        finally:reader.close()
        before=(self.base/'active-binding.private.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'capture materials'):active_binding(self.base)
        self.assertEqual(before,(self.base/'active-binding.private.json').read_bytes())

    def test_initialize_marker_requires_exact_core_paths_and_archive_identity(self):
        self.setup_copy(include_secrets=True);core=self.core()
        self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),confirm='USE_VERIFIED_COPY')))
        path=self.base/'active-binding.private.json';before=path.read_bytes();binding=active_binding(self.base)
        with self.assertRaisesRegex(ValueError,'differs from prepared'):
            mark_binding_initialized(path,state=self.state,union_root=binding['union_root'],output_root=binding['output_root'])
        self.assertEqual(before,path.read_bytes())
        value=json.loads(before);value['union_id']='0'*32;atomic_json(path,value);tampered=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'initialized union differs'):
            mark_binding_initialized(path,state=binding['state'],union_root=binding['union_root'],output_root=binding['output_root'])
        self.assertEqual(tampered,path.read_bytes())

    def test_initialized_binding_still_requires_original_receipt_key_bytes(self):
        self.setup_copy(include_secrets=True);core=self.core()
        self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),confirm='USE_VERIFIED_COPY')))
        binding=active_binding(self.base);path=self.base/'active-binding.private.json'
        mark_binding_initialized(path,state=binding['state'],union_root=binding['union_root'],output_root=binding['output_root'])
        keyring=self.restored/'state'/SECRETS
        keyring.write_text(json.dumps({'databases':[]}),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'capture materials'):active_binding(self.base)

    def test_attachment_preview_recovery_dispatch_requires_explicit_offline_view(self):
        self.setup_copy();core=self.core()
        request=dict(action='prepare_attachment',logical_id='synthetic',sha='a'*64,kind='file',view='current')
        with self.assertRaisesRegex(ValueError,'offline attachment view'):core.submit(request)
        request['view']='restored'
        with patch('wechat_capture_next.attachment_actions.perform',return_value={'status':'ready'}) as perform:
            self.wait(core,core.submit(request))
        self.assertEqual(perform.call_args.args[1],'prepare_attachment')

    def setup_provenance_copy(self):
        self.prepared();self.base=self.root/'appbase';original=self.base/'provenance'
        original.mkdir(parents=True)
        from wechat_capture_next.recovery_materials import PROVENANCE_MEMBERS
        self.provenance_bytes={name:('SYNTHETIC-'+name).encode() for name in PROVENANCE_MEMBERS}
        for name,data in self.provenance_bytes.items():(original/name).write_bytes(data)
        self.paired=self.root/'provenance-pair'
        point=rolling_delivery.backup(self.state,self.formal,self.paired,provenance=original,include_secrets=True)
        self.restored=self.root/'restored';rolling_delivery.restore(self.paired,point['snapshot_id'],self.restored)
        original.rename(self.base/'unavailable-original-provenance')
        core=self.core()
        self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),confirm='USE_VERIFIED_COPY')))
        core.close()

    def test_takeover_then_two_paused_restarts_can_backup_without_original_provenance(self):
        self.setup_provenance_copy()
        self.assertFalse((self.base/'provenance').exists())
        with patch.object(CaptureService,'capture',side_effect=AssertionError('capture forbidden')):
            for number in range(2):
                binding=active_binding(self.base)
                self.assertEqual(binding['provenance_root'],self.restored/'provenance')
                core=ProductCore(**binding,repository_root=self.state_repo,union_repository=self.union_repo,
                    paired_repository=self.paired)
                try:
                    self.assertFalse(core.watching)
                    job=self.wait(core,core.submit(dict(action='backup_pair',include_secrets=True)))
                    restored_again=self.root/('rebackup-'+str(number))
                    proof=rolling_delivery.restore(self.paired,job['result']['snapshot_id'],restored_again)
                    self.assertTrue(proof['attachments_closed'])
                    for name,data in self.provenance_bytes.items():
                        self.assertEqual((restored_again/'provenance'/name).read_bytes(),data)
                finally:core.close()

    def test_initialized_takeover_rejects_changed_or_missing_recovered_provenance(self):
        self.setup_provenance_copy();binding=active_binding(self.base)
        mark_binding_initialized(self.base/'active-binding.private.json',state=binding['state'],
            union_root=binding['union_root'],output_root=binding['output_root'])
        for name,data in self.provenance_bytes.items():
            path=self.restored/'provenance'/name
            path.write_bytes(b'X'*len(data))
            with self.assertRaisesRegex(ValueError,'provenance bytes differ'):active_binding(self.base)
            path.write_bytes(data);path.unlink()
            with self.assertRaises(OSError):active_binding(self.base)
            path.write_bytes(data)
        self.assertEqual(active_binding(self.base)['provenance_root'],self.restored/'provenance')

    def test_legacy_without_provenance_does_not_adopt_unreceipted_directory(self):
        self.setup_copy(include_secrets=True);core=self.core()
        self.wait(core,core.submit(dict(action='promote_restore',path=str(self.restored),confirm='USE_VERIFIED_COPY')))
        (self.restored/'provenance').mkdir()
        (self.restored/'provenance/unreceipted').write_bytes(b'SYNTHETIC')
        self.assertNotIn('provenance_root',active_binding(self.base))

    def test_active_binding_cannot_be_overridden_by_explicit_provenance_argument(self):
        self.setup_provenance_copy();output=io.StringIO()
        # Use only a synthetic base; the host rejects before ProductCore.
        host_root=self.root/'host';host_base=host_root/'archives/wechat-next';host_base.mkdir(parents=True)
        with patch('wechat_capture_next.recovery_core.active_binding',return_value=active_binding(self.base)),\
             patch.object(product_host,'ProductCore',side_effect=AssertionError('override must not construct live core')),\
             patch('sys.stdin',io.StringIO('quit\n')),redirect_stdout(output),redirect_stderr(io.StringIO()):
            self.assertEqual(product_host.main(['--root',str(host_root),'--provenance',str(self.root/'different')]),0)
        self.assertEqual(json.loads(output.getvalue())['mode'],'recovery')

    def test_provenance_receipt_rejects_partial_pair_and_malformed_identity(self):
        self.setup_provenance_copy()
        from copy import deepcopy
        from wechat_capture_next.recovery_materials import verified_provenance_root,PROVENANCE_MEMBERS
        marker=self.restored/'DELIVERY.complete.private.json'
        original=json.loads(marker.read_text(encoding='utf-8'));snapshot=original['snapshot_id']
        relative='provenance/'+PROVENANCE_MEMBERS[0]
        broken=[]
        value=deepcopy(original);del value['restored_files'][relative];broken.append(value)
        for field,bad in (('bytes',True),('bytes',-1),('sha256','NOT-A-HASH')):
            value=deepcopy(original);value['restored_files'][relative][field]=bad;broken.append(value)
        value=deepcopy(original);value['snapshot_id']='different';broken.append(value)
        for value in broken:
            with self.subTest(value=value['snapshot_id']):
                atomic_json(marker,value)
                with self.assertRaises(ValueError):verified_provenance_root(self.restored,snapshot)
        atomic_json(marker,original)
        self.assertEqual(verified_provenance_root(self.restored,snapshot),self.restored/'provenance')


if __name__=='__main__':unittest.main()
