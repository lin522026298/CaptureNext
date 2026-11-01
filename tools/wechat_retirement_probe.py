"""Linear-metadata, held-handle Windows probe for large retirement inventories.

Read/hash only. No file disposition or deletion occurs here. Logical dependency
checks are a caller obligation; the result is point-in-time, never atomic with a
subsequent separate PowerShell deletion.
"""
from contextlib import ExitStack

from wechat_capture_next.paths import local_absolute
from wechat_capture_next.prepare_pair_restore_cleanup import _WindowsProbe
from wechat_capture_v2.common import utcnow


def exclusive_probe(root, evidence, hashes, directory_identities, final_checks):
    if local_absolute(root) != root or not evidence["deletion_candidate_clean"]:
        raise ValueError("unsafe inventory root")
    files = {row["relative"]: row for row in evidence["files"]}
    if set(files) != set(hashes):
        raise ValueError("hash inventory differs")
    children = {relative: {} for relative in directory_identities}
    for relative in [*directory_identities, *files]:
        if not relative:
            continue
        parent, _, name = relative.rpartition("/")
        if parent not in children or name in children[parent]:
            raise ValueError("invalid inventory hierarchy")
        children[parent][name] = relative in directory_identities
    native = _WindowsProbe()
    handles = {}
    with ExitStack() as stack:
        for relative in [*directory_identities, *files]:
            handle = native.open(root / relative, directory=relative in directory_identities)
            stack.callback(native.close, handle)
            handles[relative] = handle

        def verify():
            if local_absolute(root) != root:
                raise ValueError("root drift")
            for relative, handle in handles.items():
                info = native.info(handle)
                if relative in directory_identities:
                    expected = directory_identities[relative]
                    if not info["directory"] or any(info[k] != expected[k] for k in ("device", "inode", "volume_serial")):
                        raise ValueError("directory identity drift")
                else:
                    if info["directory"] or info["nlink"] != 1 or info["volume_serial"] != directory_identities[""]["volume_serial"]:
                        raise ValueError("unsafe file identity")
                    if any(info[k] != files[relative][k] for k in ("device", "inode", "bytes", "allocated_bytes", "nlink", "mtime_ns")):
                        raise ValueError("file identity drift")
            for relative in directory_identities:
                if native.names(handles[relative]) != children[relative]:
                    raise ValueError("directory child set drift")

        verify()
        for relative, row in files.items():
            digest, length = native.sha256(handles[relative])
            if digest != hashes[relative] or length != row["bytes"]:
                raise ValueError("held handle SHA differs")
        verify()
        additional = final_checks()
        verify()
    return dict(
        additional,
        target_access_probe_passed=True,
        observed_at=utcnow(),
        scope="exact target tree, all directory and file handles held together",
        access="GENERIC_READ|DELETE; OPEN_EXISTING; share=0; never delete disposition",
        directories_including_root=len(directory_identities),
        files=len(files),
        full_inventory_and_sha256_rechecked_on_held_handles=True,
        all_owned_probe_handles_closed=True,
        metadata_child_map_complexity="O(files+directories)",
        global_dependency_absence_proven=False,
        atomic_dependency_absence_proven=False,
    )
