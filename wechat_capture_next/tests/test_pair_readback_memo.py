from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import pickle
import tempfile
import threading
import unittest
from unittest.mock import patch

from wechat_capture_next import pair_readback_memo as module


class PairReadbackMemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repository'
        self.repo.mkdir()
        self.owner = dict(schema='paired-test', catalog_instance='catalog', union_id='union')
        (self.repo / 'OWNER.private.json').write_text(json.dumps(self.owner), encoding='utf-8')
        (self.repo / 'repository.sqlite').write_bytes(b'synthetic authenticated repository bytes')
        (self.repo / 'repository.lock').write_bytes(b'0')
        self.source = self.root / 'source.sqlite'
        self.source.write_bytes(b'synthetic input')
        self.args = dict(owner=self.owner, snapshot_id='a' * 64,
                         scope=dict(includes_secrets=False, source_roots=['original']),
                         profile=dict(verification='native-1', leaf_bytes=16384, object_leaf_bytes=16384),
                         input_files={'state/catalog.sqlite': self.source},
                         file_map={'state/catalog.sqlite': dict(root='b' * 64, height=0,
                                   bytes=self.source.stat().st_size,
                                   sha256=hashlib.sha256(self.source.read_bytes()).hexdigest(),
                                   leaf_bytes=16384)})
        self.proof = dict(files=1, bytes=self.source.stat().st_size, verified=True)
        self.memo = module.PairReadbackMemo()

    def remember(self, memo=None):
        (memo or self.memo).remember_verified(self.repo, **self.args, verification=self.proof)

    def lookup(self, memo=None, args=None):
        return (memo or self.memo).lookup(self.repo, **(args or self.args))

    def test_cold_instance_isolation_and_explicit_reset(self):
        self.assertIsNone(self.lookup())
        self.remember()
        self.assertEqual(self.lookup(), self.proof)
        self.assertIsNone(self.lookup(module.PairReadbackMemo()))
        self.memo.reset()
        self.assertIsNone(self.lookup())

    def test_return_and_original_mutation_cannot_pollute_saved_proof(self):
        self.remember()
        returned = self.lookup()
        returned['verified'] = False
        self.proof['verified'] = False
        self.assertIs(self.lookup()['verified'], True)

    def test_complete_binding_changes_invalidate_instead_of_retaining_old_cut(self):
        variants = []
        for name, value in (('snapshot_id', 'c' * 64), ('scope', {'includes_secrets': True}),
                            ('profile', {'verification': 'native-2'})):
            args = copy.deepcopy(self.args)
            args[name] = value
            variants.append(args)
        args = copy.deepcopy(self.args)
        args['file_map']['state/catalog.sqlite']['root'] = 'd' * 64
        variants.append(args)
        replacement = self.root / 'replacement.sqlite'
        replacement.write_bytes(self.source.read_bytes())
        args = copy.deepcopy(self.args)
        args['input_files']['state/catalog.sqlite'] = replacement
        variants.append(args)
        for args in variants:
            with self.subTest(args=args):
                self.remember()
                self.assertIsNone(self.lookup(args=args))
                self.assertIsNone(self.lookup())

    def test_every_repository_file_is_hashed_and_raw_change_invalidates(self):
        self.remember()
        original = module.digest_file
        with patch.object(module, 'digest_file', wraps=original) as digest:
            self.assertEqual(self.lookup(), self.proof)
        self.assertEqual({call.args[0].name for call in digest.call_args_list},
                         {'repository.sqlite', 'OWNER.private.json', 'repository.lock'})
        for name in ('repository.sqlite', 'repository.lock'):
            self.remember()
            path = self.repo / name
            before = path.read_bytes()
            before_stat = path.stat()
            path.write_bytes(bytes([before[0] ^ 1]) + before[1:])
            os.utime(path, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
            self.assertIsNone(self.lookup())
            path.write_bytes(before)
            self.assertIsNone(self.lookup())

    def test_owner_format_change_is_a_byte_mismatch_not_silent_adoption(self):
        self.remember()
        (self.repo / 'OWNER.private.json').write_text(json.dumps(self.owner, indent=2), encoding='utf-8')
        self.assertIsNone(self.lookup())

    def test_canonical_order_is_irrelevant_but_full_profile_and_file_map_are_bound(self):
        self.remember()
        args = copy.deepcopy(self.args)
        args['scope'] = dict(reversed(list(args['scope'].items())))
        args['profile'] = dict(reversed(list(args['profile'].items())))
        self.assertEqual(self.lookup(args=args), self.proof)
        args['profile']['object_leaf_bytes'] *= 4
        self.assertIsNone(self.lookup(args=args))
        self.remember()
        args = copy.deepcopy(self.args)
        args['file_map']['state/catalog.sqlite']['sha256'] = 'e' * 64
        self.assertIsNone(self.lookup(args=args))

    def test_identical_repository_bytes_at_another_path_are_not_the_same_cut(self):
        self.remember()
        other = self.root / 'other-repository'
        other.mkdir()
        for source in self.repo.iterdir():
            (other / source.name).write_bytes(source.read_bytes())
        self.assertIsNone(self.memo.lookup(other, **self.args))
        self.assertIsNone(self.lookup())

    def test_caller_cannot_supply_an_external_hash_or_cached_proof_payload(self):
        with self.assertRaises(TypeError):
            self.memo.lookup(self.repo, **self.args, repository_sha256={'repository.sqlite': 'f' * 64})
        with self.assertRaises(TypeError):
            self.memo.remember_verified(self.repo, **self.args, verification=self.proof,
                                        trusted_proof=b'forged')

    def test_unknown_entry_journal_owner_and_io_exception_clear_proof(self):
        for name in ('extra', 'repository.sqlite-journal', 'repository.sqlite-wal'):
            self.remember()
            path = self.repo / name
            path.write_bytes(b'not accepted')
            with self.assertRaises(ValueError):
                self.lookup()
            path.unlink()
            self.assertIsNone(self.lookup())
        self.remember()
        with patch.object(module, 'digest_file', side_effect=OSError('read failed')):
            with self.assertRaises(OSError):
                self.lookup()
        self.assertIsNone(self.lookup())
        self.remember()
        changed = dict(self.owner, union_id='foreign')
        (self.repo / 'OWNER.private.json').write_text(json.dumps(changed), encoding='utf-8')
        with self.assertRaises(ValueError):
            self.lookup()
        (self.repo / 'OWNER.private.json').write_text(json.dumps(self.owner), encoding='utf-8')
        self.assertIsNone(self.lookup())

    def test_cross_thread_use_is_rejected_and_clears_proof(self):
        self.remember()
        errors = []
        def other_worker():
            for operation in (self.lookup, self.remember):
                try:
                    operation()
                except RuntimeError as error:
                    errors.append(str(error))
        worker = threading.Thread(target=other_worker)
        worker.start()
        worker.join()
        self.assertEqual(len(errors), 2)
        self.assertIsNone(self.lookup())
        self.remember()
        self.assertEqual(self.lookup(), self.proof)

    def test_serialization_and_copy_are_rejected(self):
        self.remember()
        for operation in (pickle.dumps, copy.copy, copy.deepcopy, json.dumps):
            with self.subTest(operation=operation):
                with self.assertRaises(TypeError):
                    operation(self.memo)

    def test_failed_remember_clears_existing_proof_and_rejects_lossy_keys(self):
        self.remember()
        with self.assertRaises(ValueError):
            self.memo.remember_verified(self.repo, **self.args,
                                       verification=dict(self.proof, files=True))
        self.assertIsNone(self.lookup())
        self.remember()
        args = copy.deepcopy(self.args)
        args['scope'] = {1: 'lossy JSON key'}
        with self.assertRaises(TypeError):
            self.lookup(args=args)
        self.assertIsNone(self.lookup())

    def test_inventory_mutation_during_hash_cannot_seed(self):
        original = module.digest_file
        def add_entry(path):
            result = original(path)
            (self.repo / 'unexpected').write_bytes(b'new')
            return result
        with patch.object(module, 'digest_file', side_effect=add_entry):
            with self.assertRaises(ValueError):
                self.remember()
        (self.repo / 'unexpected').unlink()
        self.assertIsNone(self.lookup())


if __name__ == '__main__':
    unittest.main()
