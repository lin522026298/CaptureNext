"""Automatic pipeline receipts, using no real database or archive."""
from collections import OrderedDict
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

from wechat_capture_next.product import ProductCore
from wechat_capture_next.product_journal import Journal


class AutomaticPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'operations.json'

    def core(self):
        # Only the automatic hooks and the real journal are in scope. No owned
        # worker, source binding, archive, UI, or repository can be opened here.
        core=ProductCore.__new__(ProductCore)
        core.condition=threading.Condition()
        core.jobs=OrderedDict();core.receipts=OrderedDict()
        core.service=object();core.union_root=Path(self.temp.name)/'unused-union'
        core.identity_status=dict(status='pending')
        core._identity_retry_after=0;core._sync_pending=True
        core.message_recovery_completed=False
        core._sync_media=Mock()
        core.journal=Journal(self.path,core)
        return core

    def saved(self,stage):
        return json.loads(self.path.read_text(encoding='utf-8'))['pipelines'][stage]

    def test_automatic_union_success_failure_restart_retry_preserves_evidence(self):
        core=self.core()
        result=dict(current=dict(added_observations=3),stats=dict(observations=3,logical_messages=3))
        with patch('wechat_capture_next.union_archive.sync_union',return_value=result),\
             patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(names_added=2)):
            core._after_capture(dict(mode='full_reconciliation',databases=[]))
        first=self.saved('union')
        self.assertEqual(first['outcome'],'completed')
        self.assertFalse(first['pending'])
        with patch('wechat_capture_next.union_archive.sync_union',side_effect=OSError('secret-path-must-not-leak')):
            with self.assertRaises(OSError):
                core._after_capture(dict(mode='changed_shards',databases=[dict(new_versions=1)],
                    assets=dict(enabled=True,complete=True,files_seen=2,new_versions=0,errors=[])))
        failed=self.saved('union')
        self.assertEqual(self.saved('capture')['outcome'],'completed')
        self.assertEqual(self.saved('capture')['details']['mode'],'changed_shards')
        self.assertEqual(self.saved('assets')['outcome'],'completed')
        self.assertEqual(failed['outcome'],'failed')
        self.assertEqual(failed['error_type'],'OSError')
        self.assertEqual(failed['retry'],dict(action='sync_union'))
        self.assertTrue(failed['next_step']);self.assertTrue(failed['pending'])
        self.assertEqual(failed['last_success'],first['last_success'])
        self.assertEqual(failed['last_success_details'],first['details'])
        self.assertIsNone(failed['details'])
        self.assertNotIn('secret-path-must-not-leak',self.path.read_text(encoding='utf-8'))
        before=self.path.read_bytes()
        restarted=self.core()
        self.assertEqual(restarted.journal.pipelines['union'],failed)
        self.assertEqual(self.path.read_bytes(),before)
        with patch('wechat_capture_next.union_archive.sync_union',return_value=result) as sync,\
             patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(noop=True,names_added=0)):
            restarted._after_capture(dict(mode='metadata_poll',databases=[]))
            sync.assert_called_once()
        retried=self.saved('union')
        self.assertEqual(retried['outcome'],'completed')
        self.assertIsNone(retried['error_type']);self.assertIsNone(retried['retry'])
        self.assertFalse(retried['pending']);self.assertFalse(restarted._sync_pending)

    def test_identity_success_failure_restart_retry_is_independent_of_union(self):
        core=self.core()
        with patch('wechat_capture_next.union_archive.sync_union',return_value=dict(current=dict(added_observations=0),stats=dict(observations=2))),\
             patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(names_added=2)):
            core._sync()
        success=self.saved('identities');union=self.saved('union')
        with patch('wechat_capture_next.viewer_identity.sync_names',side_effect=ValueError('private message')):
            result=core._sync_names(force=True)
        failed=self.saved('identities')
        self.assertEqual(result['status'],'failed')
        self.assertEqual(failed['outcome'],'failed')
        self.assertEqual(failed['last_success'],success['last_success'])
        self.assertEqual(failed['error_type'],'ValueError')
        self.assertEqual(failed['retry'],dict(action='sync_union'))
        self.assertTrue(failed['next_step'])
        self.assertEqual(self.saved('union'),union)
        restarted=self.core()
        self.assertEqual(restarted.journal.pipelines['identities'],failed)
        with patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(names_added=1)):
            restarted._sync_names(force=True)
        retried=self.saved('identities')
        self.assertEqual(retried['outcome'],'completed');self.assertFalse(retried['pending'])
        self.assertIsNone(retried['error_type']);self.assertIsNone(retried['retry'])

    def test_missing_contact_source_is_warning_not_a_new_success(self):
        core=self.core()
        with patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(names_added=2)):
            core._sync_names()
        succeeded=self.saved('identities')
        with patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(status='source_unavailable',reason='accepted_contact_database_absent')):
            core._sync_names(force=True)
        current=self.saved('identities')
        self.assertEqual(current['outcome'],'warning');self.assertTrue(current['pending'])
        self.assertEqual(current['last_success'],succeeded['last_success'])
        self.assertEqual(current['last_success_details'],succeeded['details'])
        self.assertEqual(core.identity_status['status'],'source_unavailable')

    def test_identity_failure_does_not_block_union_or_later_explicit_retry(self):
        core=self.core()
        result=dict(current=dict(added_observations=0),stats=dict(observations=1))
        with patch('wechat_capture_next.union_archive.sync_union',return_value=result),\
             patch('wechat_capture_next.viewer_identity.sync_names',side_effect=OSError('synthetic')):
            self.assertEqual(core._sync(),result)
        self.assertEqual(self.saved('union')['outcome'],'completed')
        self.assertEqual(self.saved('identities')['outcome'],'failed')
        core._sync_media.assert_called_once()
        with patch('wechat_capture_next.union_archive.sync_union',return_value=result),\
             patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(names_added=1)) as names:
            core._sync()
            names.assert_called_once()
        self.assertEqual(self.saved('identities')['outcome'],'completed')

    def test_idle_metadata_polls_do_not_write_or_retry_during_identity_backoff(self):
        core=self.core();core._sync_pending=False
        with patch('wechat_capture_next.viewer_identity.sync_names',side_effect=OSError('synthetic')):
            core._sync_names()
        before=self.path.read_bytes()
        with patch.object(core.journal,'save',wraps=core.journal.save) as save,\
             patch('wechat_capture_next.viewer_identity.sync_names') as names,\
             patch('wechat_capture_next.union_archive.sync_union') as union:
            for _ in range(200):core._after_capture(dict(mode='metadata_poll',databases=[]))
            save.assert_not_called();names.assert_not_called();union.assert_not_called()
        self.assertEqual(self.path.read_bytes(),before)
        with patch('wechat_capture_next.viewer_identity.sync_names',return_value=dict(noop=True,names_added=0)):
            core._sync_names(force=True)
        before=self.path.read_bytes()
        with patch.object(core.journal,'save',wraps=core.journal.save) as save:
            for _ in range(200):core._after_capture(dict(mode='metadata_poll',databases=[]))
            save.assert_not_called()
        self.assertEqual(self.path.read_bytes(),before)

    def test_crashed_automatic_attempt_is_interrupted_without_losing_success(self):
        core=self.core()
        core.journal.health(core,'identities','completed',details=dict(names_added=2))
        success=self.saved('identities')
        core.journal.health(core,'identities','running',retry=dict(action='sync_union'),next_step='稍后重试。')
        restarted=self.core();current=self.saved('identities')
        self.assertEqual(current['outcome'],'interrupted_unconfirmed')
        self.assertEqual(current['last_success'],success['last_success'])
        self.assertTrue(current['pending']);self.assertEqual(current['retry'],dict(action='sync_union'))
        self.assertEqual(restarted.journal.pipelines['identities'],current)
        before=self.path.read_bytes();self.core()
        self.assertEqual(self.path.read_bytes(),before)


if __name__=='__main__':unittest.main()
