"""Independent non-deleting probes for the ignored final cleanup mechanism.

The real script dispatcher/PowerShell are never executed. Functions are loaded
from source and rebound to a fresh tiny synthetic root, never formal data.
These are optional historical contracts for one-time ignored cleanup scripts,
not core module regressions; fresh checkouts need not contain those scripts.
"""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from wechat_capture_next.storage_ledger import verify_inventory


WORKSPACE = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = (WORKSPACE/'working/wechat_capture_release_20261020',
                WORKSPACE/'archives/wechat-next/acceptance/maintenance')


def find_source(name):
    for directory in SOURCE_ROOTS:
        candidate = directory/name
        if candidate.is_file():
            return candidate
    raise unittest.SkipTest('Optional historical contract probes for one-time cleanup scripts, '
        'not core module regression: private release and acceptance maintenance '
        f'sources are unavailable ({name}).')


SOURCES = {name: find_source(name) for name in ('final_cleanup_gate.py', 'bundle_evidence.py')}


def library(root):
    source = SOURCES['final_cleanup_gate.py']
    tree = ast.parse(source.read_text(encoding='utf-8'))
    prefix = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'mode' for target in statement.targets):
            break
        prefix.append(statement)
    namespace = {'__file__': str(source)}
    exec(compile(ast.Module(body=prefix, type_ignores=[]), str(source), 'exec'), namespace)
    original_root = namespace['ROOT']
    namespace['PROTECTED'] = [root/path.relative_to(original_root) for path in namespace['PROTECTED']]
    namespace['ROOT'] = root
    namespace['OUT'] = root/'archives/wechat-next/acceptance'
    namespace['PLAN'] = namespace['OUT']/'FINAL-CLEANUP-PLAN.private.json'
    return namespace


class CleanupNonDeletingReview(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cleanup-gate-review-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.gate = library(self.root)
        (self.root/'working').mkdir()
        (self.root/'exports').mkdir()

    def test_formal_sources_secrets_broad_roots_and_ancestors_are_never_candidates(self):
        paths = [self.root, self.root/'working', self.root/'exports',
            self.root/'wechat_capture_v2', self.root/'archives/wechat-next/acceptance',
            self.root/'archives/wechat-next/provenance',
            self.root/'working/reverse_20261015',
            self.root/'working/reverse_20261015/currentpc_20261015_B0',
            self.root/'working/oldpc_3.9.12.51_20260809',
            self.root/'working/test/90_secrets_plaintext_restricted/keyring.json']
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.gate['boundary'](path)
        candidate = self.root/'working/synthetic-candidate'
        candidate.mkdir()
        self.assertEqual(self.gate['boundary'](candidate), candidate)

    def test_same_size_restored_mtime_content_mutation_is_rejected(self):
        candidate = self.root/'exports/derived'
        candidate.mkdir()
        path = candidate/'evidence.json'
        path.write_bytes(b'A'*32)
        entry = self.gate['inspect'](candidate)
        self.gate['verify_entry'](entry)
        before = path.stat()
        path.write_bytes(b'B'*32)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        # Confirm this is the exact metadata-only false-negative boundary.
        verify_inventory(entry)
        with self.assertRaisesRegex(ValueError, 'Content drift'):
            self.gate['verify_entry'](entry)
        self.assertEqual(path.read_bytes(), b'B'*32)

    def test_hardlinked_members_are_rejected_without_altering_either_name(self):
        candidate = self.root/'working/hardlinked-derived'
        candidate.mkdir()
        original = candidate/'original'
        original.write_bytes(b'not deleted')
        alias = self.root/'outside-alias'
        os.link(original, alias)
        with self.assertRaisesRegex(ValueError, 'Linked'):
            self.gate['inspect'](candidate)
        self.assertEqual(original.read_bytes(), b'not deleted')
        self.assertEqual(alias.read_bytes(), b'not deleted')

    def test_optimized_python_refuses_both_tools_before_creating_output(self):
        code = '''
import ast
from pathlib import Path
import sys
path = Path(sys.argv[1])
tree = ast.parse(path.read_text(encoding='utf-8'))
prefix = []
for statement in tree.body:
    prefix.append(statement)
    if isinstance(statement, ast.If) and 'sys.flags.optimize' in ast.unparse(statement.test):
        break
else:
    raise AssertionError('missing optimization guard')
exec(compile(ast.Module(body=prefix, type_ignores=[]), str(path), 'exec'), {})
raise AssertionError('optimized guard did not refuse')
'''
        env = dict(os.environ)
        env['PYTHONPATH'] = str(WORKSPACE) + os.pathsep + env.get('PYTHONPATH', '')
        for name in ('final_cleanup_gate.py', 'bundle_evidence.py'):
            with self.subTest(name=name):
                child = subprocess.run([sys.executable, '-O', '-c', code, str(SOURCES[name])],
                    cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(child.returncode, 0)
                self.assertIn('Optimized Python is forbidden', child.stderr)
                self.assertFalse((self.root/'archives').exists())

    def test_verified_plan_cannot_silently_switch_to_a_new_restore_cut(self):
        candidate = self.root/'working/derived.json'
        candidate.write_bytes(b'unchanged reviewed bytes')
        entry = self.gate['inspect'](candidate)
        out = self.gate['OUT']
        out.mkdir(parents=True)
        self.gate['PLAN'].write_text(json.dumps(dict(project=str(self.root),
            union_snapshot='old-reviewed-cut', entries=[entry])), encoding='utf-8')
        self.gate['gates'] = lambda: {'union_snapshot_id': 'different-restored-cut'}
        self.gate['sys'] = SimpleNamespace(argv=['synthetic-script', 'verify'])
        tree = ast.parse(SOURCES['final_cleanup_gate.py'].read_text(encoding='utf-8'))
        dispatcher = []
        for statement in tree.body:
            if isinstance(statement, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == 'mode' for target in statement.targets):
                dispatcher = tree.body[tree.body.index(statement):]
                break
        self.assertTrue(dispatcher)
        with self.assertRaisesRegex(ValueError, 'Plan/restore snapshot drift'):
            exec(compile(ast.Module(body=dispatcher, type_ignores=[]),
                'synthetic-cleanup-dispatcher', 'exec'), self.gate)
        self.assertEqual(candidate.read_bytes(), b'unchanged reviewed bytes')


if __name__ == '__main__':
    unittest.main()
