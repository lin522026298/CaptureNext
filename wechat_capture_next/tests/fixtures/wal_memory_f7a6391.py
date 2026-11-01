"""Seekable WAL snapshot: RAM first, disk spill for arbitrarily large input.

Audit is the frozen v2 wal_prefix algorithm with only the stream boundary
changed. Compare its complete output with v2 in tests; never weaken any frame
checksum, salt, HMAC, tail or commit-boundary rule to avoid temporary writes.
"""
from contextlib import contextmanager
import hashlib
import struct
import tempfile

from tools.sqlite_wal import checksum
from wechat_capture_v2.cipher import PAGE, STRIDE
from wechat_capture_v2.common import regular


@contextmanager
def freeze_wal(path, directory, memory_bytes=64*1024**2):
    if isinstance(memory_bytes, bool) or not isinstance(memory_bytes, int) or memory_bytes < 0:
        raise ValueError('nonnegative WAL buffer size required')
    count = regular(path).st_size
    with tempfile.SpooledTemporaryFile(max_size=memory_bytes, mode='w+b', dir=directory) as stream:
        if memory_bytes == 0:  # Explicit FILE baseline for evidence, not an input limit.
            stream.rollover()
        with path.open('rb') as live:
            remaining = count
            while remaining:
                block = live.read(min(1024**2, remaining))
                if not block:
                    raise RuntimeError('WAL truncated during freeze')
                stream.write(block)
                remaining -= len(block)
        stream.flush()
        stream.seek(0)
        yield stream, count, bool(stream._rolled)


def stream_prefix_hash(stream, count):
    stream.seek(0)
    digest = hashlib.sha256()
    while count:
        block = stream.read(min(1024**2, count))
        if not block:
            raise RuntimeError('frozen WAL prefix shrank')
        digest.update(block)
        count -= len(block)
    return digest.hexdigest()


def stream_wal_prefix(stream, size, cipher=None):
    result = dict(physical_bytes=size, committed_bytes=0, last_commit_frame=0,
        committed_database_pages=None, valid_frames=0, tail_reason=None)
    stream.seek(0)
    if size == 0:
        result['tail_reason'] = 'empty'
        return result
    header = stream.read(32)
    if len(header) != 32:
        raise ValueError('incomplete WAL header')
    magic, version, page_size = struct.unpack_from('>III', header)
    if magic not in (0x377F0682, 0x377F0683) or version != 3007000 or page_size != PAGE:
        raise ValueError('unsupported WAL header')
    big = magic == 0x377F0683
    state = checksum(header[:24], big_endian=big)
    if state != struct.unpack_from('>II', header, 24):
        raise ValueError('WAL header checksum failed')
    salts = header[16:24]
    frame = 0
    while stream.tell() < size:
        data = stream.read(STRIDE)
        if len(data) < STRIDE:
            result['tail_reason'] = 'incomplete_uncommitted_tail'
            break
        frame += 1
        fh, page = data[:24], data[24:]
        number, pages = struct.unpack_from('>II', fh)
        if fh[8:16] != salts:
            result['tail_reason'] = 'stale_generation_tail'
            break
        if number in (0, 0xFFFFFFFF) or pages == 0xFFFFFFFF:
            result['tail_reason'] = 'invalid_frame_tail'
            break
        expected = checksum(fh[:8]+page, state, big)
        if expected != struct.unpack_from('>II', fh, 16):
            result['tail_reason'] = 'checksum_tail'
            break
        if cipher is not None:
            cipher.decrypt(page, number)
        state = expected
        result['valid_frames'] = frame
        if pages:
            result.update(last_commit_frame=frame, committed_database_pages=pages,
                committed_bytes=32+frame*STRIDE)
    return result
