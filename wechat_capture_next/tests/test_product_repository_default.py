"""Host wiring only: no core, server, repository, source, or UI is opened."""
from contextlib import nullcontext,redirect_stdout,redirect_stderr
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from wechat_capture_next import product_host


class RepositoryDefaultTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.base=self.root/'archives/wechat-next'

    def launch(self,mode,*,explicit=False,binding=None):
        expected=self.root/'explicit-paired' if explicit else self.base/'backups/paired-v3'
        args=['--root',str(self.root)]
        if mode=='recovery':args.append('--recovery')
        if mode=='offline':args.extend(['--offline',str(self.root/'synthetic-offline')])
        if explicit:args.extend(['--paired-repo',str(expected)])
        normal=Mock()
        normal.control_snapshot.return_value=dict(product=dict(mode='normal'))
        recovery=Mock()
        recovery.control_snapshot.return_value=dict(product=dict(mode='recovery'))
        listener=SimpleNamespace(base_url='http://127.0.0.1:1',token='synthetic-token')
        host=Mock(desktop=[listener])
        output=io.StringIO()
        with patch('wechat_capture_next.product_host.ProductCore',return_value=normal,
                side_effect=ValueError('synthetic startup failure') if mode=='fallback' else None) as product,\
             patch('wechat_capture_next.recovery_core.RecoveryCore',return_value=recovery) as offline,\
             patch('wechat_capture_next.recovery_core.active_binding',return_value=binding) as active,\
             patch('wechat_capture_next.recovery_core.binding_lock',return_value=nullcontext()),\
             patch('wechat_capture_next.product_host.ProductHost',return_value=host) as factory,\
             patch('sys.stdin',io.StringIO('quit\n')),redirect_stdout(output),redirect_stderr(io.StringIO()):
            self.assertEqual(product_host.main(args),0)
        chosen=product if mode=='normal' else offline
        self.assertEqual(chosen.call_args.kwargs['paired_repository'],expected)
        if mode=='fallback':
            self.assertEqual(product.call_args.kwargs['paired_repository'],expected)
            self.assertEqual(offline.call_args.kwargs['reason'],'formal_startup_unavailable_ValueError')
        if mode in ('recovery','offline'):
            product.assert_not_called();active.assert_not_called()
        if mode=='offline':self.assertEqual(offline.call_args.kwargs['offline'],self.root/'synthetic-offline')
        self.assertEqual(json.loads(output.getvalue())['mode'],'normal' if mode=='normal' else 'recovery')
        factory.assert_called_once_with(normal if mode=='normal' else recovery)
        host.close.assert_called_once()
        # The constructors are mocks: no old/new repository may be created,
        # adopted, inspected, or migrated by this host-argument wiring test.
        self.assertFalse((self.base/'backups').exists())
        return chosen.call_args.kwargs

    def test_default_common_is_shared_by_normal_recovery_offline_and_fallback(self):
        for mode in ('normal','recovery','offline','fallback'):
            with self.subTest(mode=mode):self.launch(mode)

    def test_explicit_repository_overrides_default_in_every_mode(self):
        for mode in ('normal','recovery','offline','fallback'):
            with self.subTest(mode=mode):self.launch(mode,explicit=True)

    def test_active_binding_selects_state_not_repository_and_marker_is_untouched(self):
        self.base.mkdir(parents=True)
        marker=self.base/'active-binding.private.json'
        original=b'{"synthetic":"read-only-marker-evidence"}'
        marker.write_bytes(original)
        binding=dict(state=self.root/'recovered/state',union_root=self.root/'recovered/union',
            output_root=self.base/'product-sessions'/('a'*32),start_paused=True,active_binding_path=marker)
        for explicit in (False,True):
            with self.subTest(explicit=explicit):
                passed=self.launch('normal',explicit=explicit,binding=binding)
                for key,value in binding.items():self.assertEqual(passed[key],value)
                self.assertEqual(marker.read_bytes(),original)
        self.assertEqual(binding['active_binding_path'],marker)


if __name__=='__main__':unittest.main()
