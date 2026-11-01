#!/usr/bin/env python3
"""Verify a JSONL content manifest embedded in a ZIP without extracting it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile


def sha256_stream(handle) -> str:
    digest = hashlib.sha256()
    while chunk := handle.read(4 * 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def safe_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not value or "\\" in value or ".." in path.parts:
        raise ValueError(f"unsafe manifest path: {value!r}")
    return path.as_posix()


def verify(zip_path: Path, manifest_suffix: str, sidecar_suffix: str) -> dict:
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        roots = {name.split("/", 1)[0] for name in names if name}
        if len(roots) != 1:
            raise ValueError(f"expected one ZIP root, got {sorted(roots)!r}")
        root = next(iter(roots))
        manifest_name = next(
            (name for name in names if name.endswith(manifest_suffix)), None
        )
        sidecar_name = next(
            (name for name in names if name.endswith(sidecar_suffix)), None
        )
        if manifest_name is None or sidecar_name is None:
            raise FileNotFoundError("manifest or sidecar is absent from ZIP")

        manifest_bytes = archive.read(manifest_name)
        sidecar_text = archive.read(sidecar_name).decode("utf-8-sig").strip()
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        sidecar_expected = sidecar_text.split()[0].casefold()
        sidecar_match = manifest_sha256 == sidecar_expected

        records = []
        for line_number, raw_line in enumerate(manifest_bytes.splitlines(), start=1):
            if not raw_line.strip():
                continue
            record = json.loads(raw_line)
            relative = safe_relative_path(record["relative_path"])
            records.append(
                {
                    "line": line_number,
                    "relative_path": relative,
                    "length": int(record["length"]),
                    "sha256": str(record["sha256"]).casefold(),
                }
            )

        duplicate_paths = len(records) - len(
            {record["relative_path"].casefold() for record in records}
        )
        archive_files = {
            name: info
            for info in archive.infolist()
            if not info.is_dir()
            for name in [info.filename]
        }
        expected_archive_names = {
            record["relative_path"]: f"{root}/{record['relative_path']}"
            for record in records
        }
        missing = [
            relative
            for relative, archive_name in expected_archive_names.items()
            if archive_name not in archive_files
        ]
        length_mismatches = []
        hash_mismatches = []
        verified_bytes = 0
        verified_files = 0

        if sidecar_match and duplicate_paths == 0 and not missing:
            for record in records:
                archive_name = expected_archive_names[record["relative_path"]]
                info = archive_files[archive_name]
                if info.file_size != record["length"]:
                    length_mismatches.append(
                        {
                            "relative_path": record["relative_path"],
                            "manifest": record["length"],
                            "zip": info.file_size,
                        }
                    )
                    continue
                with archive.open(info, "r") as handle:
                    actual = sha256_stream(handle)
                if actual != record["sha256"]:
                    hash_mismatches.append(
                        {
                            "relative_path": record["relative_path"],
                            "expected": record["sha256"],
                            "actual": actual,
                        }
                    )
                    continue
                verified_files += 1
                verified_bytes += info.file_size

        manifest_names = set(expected_archive_names.values())
        excluded_archive_files = sorted(set(archive_files) - manifest_names)
        passed = (
            sidecar_match
            and duplicate_paths == 0
            and not missing
            and not length_mismatches
            and not hash_mismatches
            and verified_files == len(records)
        )
        return {
            "zip": str(zip_path.resolve()),
            "zip_file_count": len(archive_files),
            "zip_single_root": root,
            "manifest_entry": manifest_name,
            "manifest_sha256": manifest_sha256,
            "manifest_sidecar_match": sidecar_match,
            "manifest_record_count": len(records),
            "manifest_duplicate_path_count": duplicate_paths,
            "missing_count": len(missing),
            "length_mismatch_count": len(length_mismatches),
            "hash_mismatch_count": len(hash_mismatches),
            "verified_file_count": verified_files,
            "verified_bytes": verified_bytes,
            "archive_files_excluded_from_manifest": excluded_archive_files,
            "pass": passed,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path)
    parser.add_argument(
        "--manifest-suffix",
        default="/20_MANIFESTS/FINAL_CONTENT_MANIFEST.jsonl",
    )
    parser.add_argument(
        "--sidecar-suffix",
        default="/20_MANIFESTS/FINAL_CONTENT_MANIFEST.sha256",
    )
    args = parser.parse_args()
    result = verify(args.zip_path, args.manifest_suffix, args.sidecar_suffix)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
