#!/usr/bin/env python3
"""Read-only legacy/V1/V2 DAT decoder. Never discovers accounts or processes.

The default CLI only validates a supplied file. Optional image output is exclusive
creation: the source and an existing destination are never overwritten.
Dependencies: cryptography, Pillow. No third-party WeChat module is imported.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import warnings

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

V1_MAGIC = bytes.fromhex("070856310807")
V2_MAGIC = bytes.fromhex("070856320807")
V1_KEY = b"cfcd208495d565ef"
MAX_BYTES = 64 * 1024 * 1024
SIGNATURES = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"BM", b"RIFF")


class DecodeError(ValueError):
    """Unknown format, invalid envelope/key, or failed full image validation."""


@dataclass(frozen=True)
class Candidate:
    key: bytes
    xor_byte: int
    label: str = "supplied"


@dataclass(frozen=True)
class Decoded:
    data: bytes
    method: str
    image_format: str
    dimensions: tuple[int, int]
    frames: int
    candidate_label: str | None = None

    def summary(self) -> dict:
        return {"method": self.method, "format": self.image_format,
                "dimensions": self.dimensions, "frames": self.frames,
                "bytes": len(self.data), "sha256": hashlib.sha256(self.data).hexdigest(),
                "candidate_label": self.candidate_label}


def derive_v2_key(code: int, username: str) -> Candidate:
    """Community formula, locally verified for part of the frozen 4.1.12.26 set.

    This is the first 16 *ASCII hex characters*, not a 16-byte hex decoding.
    The caller supplies identity candidates; this function never guesses a user.
    """
    if not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 0xFFFFFFFF:
        raise ValueError("code must be an unsigned 32-bit integer")
    if not username:
        raise ValueError("username must not be empty")
    key = hashlib.md5((str(code) + username).encode("utf-8")).hexdigest()[:16].encode("ascii")
    return Candidate(key, code & 255)


def decrypt_envelope(blob: bytes, key: bytes, xor_byte: int) -> bytes:
    """Strict 15-byte V1/V2 envelope: AES-ECB/PKCS7, raw middle, XOR tail.

    Header fields @6 and @10 are little-endian plaintext-AES and XOR lengths.
    A full padding block is present even when the AES plaintext is aligned.
    The flag byte @14 is preserved as an unassigned field, not interpreted.
    """
    if len(blob) > MAX_BYTES or len(blob) < 15 or blob[:6] not in (V1_MAGIC, V2_MAGIC):
        raise DecodeError("unsupported or oversized envelope")
    if len(key) != 16 or not isinstance(xor_byte, int) or not 0 <= xor_byte <= 255:
        raise ValueError("expected AES-128 key and one XOR byte")
    aes_size, xor_size = struct.unpack_from("<II", blob, 6)
    encrypted_size = (aes_size // 16 + 1) * 16
    aes_end, tail_begin = 15 + encrypted_size, len(blob) - xor_size
    if aes_end > tail_begin or tail_begin > len(blob):
        raise DecodeError("inconsistent envelope lengths")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    prefix = decryptor.update(blob[15:aes_end]) + decryptor.finalize()
    pad = prefix[-1]
    if not 1 <= pad <= 16 or prefix[-pad:] != bytes([pad]) * pad:
        raise DecodeError("invalid AES padding or wrong key")
    prefix = prefix[:-pad]
    if len(prefix) != aes_size:
        raise DecodeError("AES plaintext length disagrees with header")
    return prefix + blob[aes_end:tail_begin] + bytes(b ^ xor_byte for b in blob[tail_begin:])


def validate_image(data: bytes) -> tuple[str, tuple[int, int], int]:
    """Require parser verification and pixel decoding of every image frame."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as image:
                image.verify()
            with Image.open(BytesIO(data)) as image:
                fmt, size, frames = image.format, image.size, getattr(image, "n_frames", 1)
                if frames > 4096:
                    raise DecodeError("too many frames")
                for frame in range(frames):
                    image.seek(frame)
                    image.load()
                return fmt or "unknown", size, frames
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("image verify/pixel decode failed") from exc


def decode(blob: bytes, candidates: tuple[Candidate, ...] = ()) -> Decoded:
    if not blob or len(blob) > MAX_BYTES:
        raise DecodeError("empty or oversized DAT")
    if blob[:6] in (V1_MAGIC, V2_MAGIC):
        if blob[:6] == V1_MAGIC:
            choices = {c.xor_byte for c in candidates}
            if len(blob) >= 15 and struct.unpack_from("<I", blob, 10)[0] == 0:
                choices.add(0)
            if len(blob) >= 2 and blob[-1] ^ 0xD9 == blob[-2] ^ 0xFF:
                choices.add(blob[-1] ^ 0xD9)
            keys = tuple(Candidate(V1_KEY, x, "v1-fixed") for x in sorted(choices))
            method = "v1-aes-pkcs7-raw-xor"
        else:
            keys, method = candidates, "v2-aes-pkcs7-raw-xor"
        for candidate in keys:
            try:
                plain = decrypt_envelope(blob, candidate.key, candidate.xor_byte)
                fmt, size, frames = validate_image(plain)
                return Decoded(plain, method, fmt, size, frames, candidate.label)
            except DecodeError:
                continue
        raise DecodeError("no supplied candidate passed envelope and full image validation")
    for signature in SIGNATURES:
        if len(blob) < len(signature):
            continue
        xor = blob[0] ^ signature[0]
        if bytes(b ^ xor for b in blob[:len(signature)]) != signature:
            continue
        plain = bytes(b ^ xor for b in blob)
        try:
            fmt, size, frames = validate_image(plain)
            return Decoded(plain, "legacy-single-byte-xor", fmt, size, frames)
        except DecodeError:
            continue
    raise DecodeError("unknown DAT or failed image validation")


def load_candidates(path: Path) -> tuple[Candidate, ...]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    return tuple(Candidate(bytes.fromhex(row["aes_hex"]), row["xor_byte"],
                           row.get("candidate_id", "supplied"))
                 for row in payload["entries"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("--keyring", type=Path)
    ap.add_argument("--out", type=Path, help="optional new destination; existing file is never replaced")
    args = ap.parse_args()
    if args.input.stat().st_size > MAX_BYTES:
        ap.error("input exceeds 64 MiB limit")
    blob = args.input.read_bytes()
    candidates = load_candidates(args.keyring) if args.keyring else ()
    try:
        result = decode(blob, candidates)
    except DecodeError as exc:
        print(json.dumps({"pass": False, "reason": str(exc)}))
        return 1
    if args.out:
        with args.out.open("xb") as handle:
            handle.write(result.data)
    print(json.dumps({"pass": True, "source_sha256": hashlib.sha256(blob).hexdigest(),
                      **result.summary()}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
