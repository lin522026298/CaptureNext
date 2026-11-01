"""Reproduce operation-local I/O savings using synthetic temporary data only.

Run: python -m wechat_capture_next.tests.benchmark_io_cost
No live configuration, archive, phone, or WeChat process is inspected. Baseline
source is an included frozen snapshot, evaluated in memory with current fixtures.
This is a mechanism comparison, not a physical-disk benchmark or real-workload
speedup forecast. Elapsed times are single warm/cache-affected observations.
"""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import time
import types
from unittest.mock import patch

from wechat_capture_next import backup as current
from wechat_capture_next.wal_memory import stream_wal_prefix
from wechat_capture_next.tests.test_backup import BackupTests
from wechat_capture_next.tests.test_materialize import ChangedWriteTests
from wechat_capture_v2.tests.test_backend import KEY, encrypt, make_wal
from wechat_capture_v2.cipher import PageCipher


def _baseline(name, revision):
    frozen=Path(__file__).with_name('fixtures')/(name+'_f7a6391.py')
    source = (frozen.read_text(encoding='utf-8') if revision=='f7a6391' else
        subprocess.check_output(['git', 'show',
            revision+':wechat_capture_next/'+name+'.py'], text=True, encoding='utf-8'))
    module = types.ModuleType('wechat_capture_next._benchmark_baseline_'+name)
    module.__file__ = str(Path('wechat_capture_next', name+'.py').absolute())
    exec(compile(source, module.__file__, 'exec'), module.__dict__)
    return module


class _Counter(io.BytesIO):
    bytes_read = 0

    def read(self, count=-1):
        value = super().read(count)
        self.bytes_read += len(value)
        return value


def run(revision='f7a6391'):
    old_wal, old_backup = _baseline('wal_memory', revision), _baseline('backup', revision)
    walcase = ChangedWriteTests()
    walcase.setUp()
    try:
        page = encrypt(walcase.pages()[0], 1)
        make_wal(walcase.wal, [(1, len(walcase.pages()), page)]*2048)
        blob = walcase.wal.read_bytes()
        wal_results = []
        for name, module in [('baseline', old_wal), ('optimized', None)]:
            stream = _Counter(blob)
            cipher = PageCipher(KEY, walcase.source.read_bytes()[:16])
            started = time.perf_counter()
            with patch.object(cipher, 'decrypt', wraps=cipher.decrypt) as decrypt:
                if module:
                    audit = module.stream_wal_prefix(stream, len(blob), cipher)
                    hashes = [module.stream_prefix_hash(stream, audit['committed_bytes']) for _ in range(3)]
                    proof = {'committed': hashes[0], 'verification': hashes[0]}
                else:
                    proof = {}
                    audit = stream_wal_prefix(stream, len(blob), cipher,
                        prefix_hashes=proof, authentication_only=True)
                result = dict(name=name, seconds=time.perf_counter()-started,
                    frozen_stream_bytes_read=stream.bytes_read,
                    AES_decryptions=decrypt.call_count, valid_frames=audit['valid_frames'],
                    committed_SHA256=proof['committed'])
            wal_results.append(result)
        assert wal_results[0]['committed_SHA256'] == wal_results[1]['committed_SHA256']
    finally:
        walcase.tearDown()
    case = BackupTests()
    case.setUp()
    try:
        service = case.prepared()
        block = b'repeated'*(current.CHUNK_BYTES//8)
        key = hashlib.sha256(block).hexdigest()
        for name in ['a.json', 'b.json', 'c.json']:
            (service.state/'reports'/name).write_bytes(block*8)
        backup_results = []
        for name, module in [('baseline', old_backup), ('optimized', current)]:
            repo = case.root/('repository-'+name)
            first = module.backup(service, repo)
            original_block, original_integrity = module._block, module._integrity
            counts = dict(repeated_payload_readbacks=0, pages_integrity_scans=0)

            def count_block(db, current_key):
                if current_key == key:
                    counts['repeated_payload_readbacks'] += 1
                return original_block(db, current_key)

            def count_integrity(db):
                if db.execute('PRAGMA database_list').fetchone()[2].endswith('.pages.sqlite'):
                    counts['pages_integrity_scans'] += 1
                return original_integrity(db)

            before = current.digest_file(repo/current.DATABASE)
            started = time.perf_counter()
            with patch.object(module, '_block', side_effect=count_block), \
                    patch.object(module, '_integrity', side_effect=count_integrity):
                second = module.backup(service, repo)
            elapsed = time.perf_counter()-started
            assert second['noop'] and second['snapshot_id'] == first['snapshot_id']
            assert before == current.digest_file(repo/current.DATABASE)
            backup_results.append(dict(name=name, seconds=elapsed, **counts,
                readback_uncompressed_bytes=counts['repeated_payload_readbacks']*len(block),
                snapshot_id=second['snapshot_id'], noop=True, repository_SHA256_unchanged=True))
        assert backup_results[0]['snapshot_id'] == backup_results[1]['snapshot_id']
    finally:
        case.tearDown()
    sources = {name: hashlib.sha256(Path('wechat_capture_next', name+'.py').read_bytes()).hexdigest()
               for name in ('backup', 'materialize', 'wal_memory')}
    return dict(baseline=revision, synthetic_only=True, current_source_SHA256=sources,
        limitations='Single cached synthetic run; no physical disk I/O or real workload extrapolation.',
        wal=wal_results, backup_24MiB_repeated_reports=backup_results)


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
