"""Disposable, RAM-only attachment views of authenticated retained originals.

The cache does not discover files, resolve user-supplied paths, execute files,
fetch URLs, decode video, or create plaintext temporary files. A recognized
container can be offered to a browser, but is not evidence of playable video.
Preview limits never limit original acquisition, retention, or raw export.
"""
from collections import OrderedDict
import codecs
import hashlib
from pathlib import PureWindowsPath
import re
import threading

from . import file_media
from .media_preview import BinaryMedia


MAX_ATTACHMENT = 64 * 1024**2
BUDGET = 128 * 1024**2
MAX_ENTRIES = 256
CODEC = 'authenticated-ram-attachment-1'
TEXT_EXTENSIONS = frozenset(('.txt', '.log', '.csv', '.md', '.json', '.xml'))
MP4_BRANDS = frozenset((b'isom', b'iso2', b'iso3', b'iso4', b'iso5', b'iso6',
    b'iso7', b'iso8', b'iso9', b'mp41', b'mp42', b'avc1', b'dash', b'M4V ',
    b'M4VH', b'M4VP'))


def _video_mime(data):
    """Conservative MP4 ftyp recognition, not a decoder or playback check.

    WebM, Ogg, encrypted/unknown variants, and misleading extensions stay raw.
    A generic EBML or Ogg header does not establish a video codec.
    """
    if len(data) < 16 or data[4:8] != b'ftyp':
        return None
    size = int.from_bytes(data[:4], 'big')
    if size < 16 or size > min(len(data), 4096) or size % 4:
        return None
    # Require a recognized major brand; compatible-brand claims alone are not
    # enough to treat an otherwise unknown container as this preview format.
    if data[8:12] not in MP4_BRANDS:
        return None
    return 'video/mp4'


def _text_allowed(row):
    # Filename claims are only type hints, never file paths or execution targets.
    return any(PureWindowsPath(e['claim']['filename']).suffix.casefold() in TEXT_EXTENSIONS
        for e in row['evidence'] if e['claim'].get('filename'))


def _preview_type(data, row, kind):
    mime = _video_mime(data)
    if mime:
        return 'video', mime, None
    if kind == 'video':
        return None, None, 'unsupported_or_malformed_video_container'
    if _text_allowed(row):
        decoder = codecs.getincrementaldecoder('utf-8')(errors='strict')
        try:
            # Keep Unicode validation buffers small even for a 64 MiB text
            # attachment; a full second Unicode copy is unnecessary.
            for offset in range(0, len(data), 64 * 1024):
                text = decoder.decode(data[offset:offset + 64 * 1024])
                if any(ord(c) < 32 and c not in '\t\r\n' for c in text):
                    return None, None, 'binary_control_characters_not_text'
            decoder.decode(b'', final=True)
        except UnicodeDecodeError:
            return None, None, 'text_is_not_strict_utf8'
        return 'text', 'text/plain; charset=utf-8', None
    return None, None, 'unsupported_attachment_type_saved_raw'


class AttachmentCache:
    """Bounded LRU of immutable BinaryMedia payloads, never originals on disk.

Preparation is serialized with cache reads/clear, bounding concurrent buffers.
Every prepare fully authenticates the current bound CAS, including a cache hit;
only byte payloads are reused. Association evidence is rebuilt per message.
"""

    def __init__(self, *, budget=BUDGET, max_item=MAX_ATTACHMENT):
        if type(budget) is not int or budget < 1 or type(max_item) is not int or max_item < 1:
            raise ValueError('positive attachment preview memory bounds required')
        self.budget = budget
        self.max_item = min(max_item, MAX_ATTACHMENT)
        self.lock = threading.Lock()
        self.entries = OrderedDict()
        self.bytes = 0

    def read(self, ident):
        if not isinstance(ident, str) or not re.fullmatch('[0-9a-f]{64}', ident):
            raise ValueError('invalid attachment artifact')
        with self.lock:
            if ident not in self.entries:
                raise KeyError('attachment preview expired; prepare again')
            binary = self.entries.pop(ident)
            self.entries[ident] = binary
            return binary

    def clear(self):
        with self.lock:
            self.entries.clear()
            self.bytes = 0

    def prepare(self, archive, catalog, objects, *, logical_id, sha, kind=None):
        row = file_media._selected(archive, catalog, logical_id, sha, kind)
        if objects.execute('SELECT 1 FROM file WHERE hash=?', (sha,)).fetchone() is None:
            return dict(status='file_missing', preview_status='file_missing',
                file_sha=sha, raw_sha=sha, bytes=row['bytes'],
                reason='selected_object_not_in_bound_cas_other_sources_not_claimed_absent',
                raw_preserved=False, sha256_original_bytes_verified=False,
                content_checksum_matches=False, origin_link_confirmed=False,
                physical_origin_confirmed=False, media_kind=None, mime=None,
                evidence=row['evidence'], evidence_count=row['evidence_count'],
                evidence_is_not_duplicate_message_identity=True,
                storage='bounded_RAM_only_no_plaintext_temp_files')
        claims = file_media.hints(archive, logical_id, kind=kind)['claims']
        # Oversized originals still receive full streaming authentication, with
        # no retained payload buffer and no acquisition/retention restriction.
        limit_reason = ('attachment_preview_size_limit_only' if row['bytes'] > self.max_item else
            'attachment_memory_preview_budget_only' if row['bytes'] > self.budget else None)
        with self.lock:
            digest = hashlib.md5()
            length = 0
            raw = bytearray() if limit_reason is None else None
            for *_, block in file_media._blocks(objects, sha, row['bytes']):
                digest.update(block)
                length += len(block)
                if raw is not None:
                    raw.extend(block)
            # _blocks checks complete SHA-256, chunk order, decompression,
            # lengths, and per-chunk hashes before this success path is reached.
            result = file_media._result(row, claims, digest.hexdigest(), length)
            result.update(association_status=result['status'], raw_sha=sha,
                physical_origin_confirmed=False, evidence=row['evidence'],
                evidence_count=row['evidence_count'],
                evidence_examples_truncated=row['evidence_examples_truncated'],
                storage='bounded_RAM_only_no_plaintext_temp_files',
                original_retention_limited=False, browser_playback_verified=False,
                media_kind=None, mime=None, reused=False,
                preview_limit_bytes=self.max_item, cache_budget_bytes=self.budget)
            if limit_reason:
                result.update(status='saved_unsupported', preview_status='saved_unsupported',
                    preview_reason=limit_reason, reason=limit_reason)
                return result
            data = bytes(raw)
            del raw
            media_kind, mime, reason = _preview_type(data, row, kind)
            if reason:
                result.update(status='saved_unsupported', preview_status='saved_unsupported',
                    preview_reason=reason, reason=reason)
                return result
            ident = hashlib.sha256((CODEC + '\0' + sha + '\0' + mime).encode('ascii')).hexdigest()
            reused = ident in self.entries
            if reused:
                binary = self.entries.pop(ident)
            else:
                binary = BinaryMedia(data, mime)
                while self.entries and (self.bytes + len(data) > self.budget or
                        len(self.entries) >= MAX_ENTRIES):
                    _, expired = self.entries.popitem(last=False)
                    self.bytes -= len(expired.data)
                self.bytes += len(data)
            self.entries[ident] = binary
            result.update(status='ready', preview_status='ready', artifact_id=ident,
                media_kind=media_kind, mime=mime, reused=reused, preview_reason=None,
                preview_bytes=len(data), cache_bytes=self.bytes,
                container_recognized=media_kind == 'video',
                playback_limitation='container_only_browser_codec_support_unverified' if media_kind == 'video' else None,
                text_rendering='plain_text_only_no_HTML_execution' if media_kind == 'text' else None)
            return result
