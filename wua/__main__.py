"""Explicit, local-only WUA operations. Run ``python -m wua --help``."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
from pathlib import Path

from .store import ArchiveStore
from .weixin4 import Weixin4Database


def import_manifest(archive: Path, manifest: dict) -> dict:
    """An input manifest is private: it may contain local paths/identities.

    source_meta/snapshot_meta describe the frozen original source and must be
    invariant across partial imports. Database hash/profile is bound to every
    observation and the returned report, not to mutable snapshot metadata.
    """
    with ExitStack() as stack:
        adapters = [stack.enter_context(Weixin4Database(
            item["path"], db_relative_path=item["relative_path"],
            account_alias=manifest["account_alias"],
            self_username=manifest.get("self_username"))) for item in manifest["databases"]]
        if not adapters:
            raise ValueError("input manifest must list at least one database")
        rows = (row for adapter in adapters for row in adapter.observations())
        with ArchiveStore(archive) as store:
            result = store.import_observations(manifest["source_meta"], manifest["snapshot_meta"], rows)
            return {"import": result, "adapters": [adapter.report() for adapter in adapters],
                    "integrity": store.integrity_check(), "semantic_digest": store.semantic_digest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    imp = commands.add_parser("import-weixin4", help="import explicitly listed decrypted frozen shards")
    imp.add_argument("--archive", required=True, type=Path)
    imp.add_argument("--input-manifest", required=True, type=Path)
    imp.add_argument("--report", required=True, type=Path, help="new private report; never overwritten")
    for name in ("stats", "query", "viewer", "export-bag"):
        child = commands.add_parser(name)
        child.add_argument("--archive", required=True, type=Path)
        if name == "query":
            child.add_argument("--search")
            child.add_argument("--conversation")
            child.add_argument("--source")
            child.add_argument("--limit", type=int, default=100)
            child.add_argument("--offset", type=int, default=0)
        elif name == "export-bag":
            child.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "import-weixin4":
        if args.report.exists():
            parser.error("report already exists; choose a new private report path")
        manifest = json.loads(args.input_manifest.read_text(encoding="utf-8-sig"))
        result = import_manifest(args.archive, manifest)
        with args.report.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
        # No message bodies, account identifiers, local input paths or keys.
        print(json.dumps(result["import"], ensure_ascii=False))
    elif args.command == "viewer":
        from .viewer import launch
        launch(args.archive)
    elif args.command == "export-bag":
        from .bag import export_bag
        print(json.dumps(export_bag(args.archive, args.out), ensure_ascii=False))
    else:
        with ArchiveStore(args.archive, readonly=True) as store:
            if args.command == "stats":
                result = {"stats": store.stats(), "integrity": store.integrity_check(),
                          "semantic_digest": store.semantic_digest()}
            else:
                result = store.list_messages(search=args.search, conversation_id=args.conversation,
                                             source_id=args.source, limit=args.limit, offset=args.offset)
            print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
