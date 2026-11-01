"""Read-only legacy preservation audit and private real-test event markers."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from .common import canonical,digest_file,utcnow,write_json_new


def protected_files(project):
    project=Path(project).resolve(strict=True)
    for relative in ("README.md",".gitignore","requirements-re.txt","requirements-viewer-build.txt"):
        if (project/relative).is_file():
            yield project/relative
    for name in ("tools","tests","wua","docs"):
        for path in (project/name).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                yield path
    for relative in ("working/reverse_20261015/currentpc_open_20261015_D/wua_two_pc.sqlite",):
        path=project/relative
        if path.is_file():
            yield path
    viewer=project/"working/reverse_20261015/viewer_dist/WUAViewer"
    if viewer.is_dir():
        for path in viewer.rglob("*"):
            if path.is_file():
                yield path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("protect","verify","event","marker","audit","suite"))
    parser.add_argument("--manifest",type=Path)
    parser.add_argument("--project",type=Path,default=Path.cwd())
    parser.add_argument("--state",type=Path)
    parser.add_argument("--label")
    parser.add_argument("--out",type=Path)
    parser.add_argument("--text",help="exact synthetic test text; no unrelated chat contents are printed")
    args=parser.parse_args()
    if args.action=='suite':
        results=[]
        for name,folder in (('new_backend','wechat_capture_v2/tests'),('legacy_regression','tests')):
            completed=subprocess.run([sys.executable,'-m','unittest','discover','-s',folder,'-q'],
                                     capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=600)
            results.append({'suite':name,'returncode':completed.returncode,'output':completed.stdout+completed.stderr})
        report={'schema':'capture-test-suites-1','time':utcnow(),'pass':all(r['returncode']==0 for r in results),'results':results}
        if args.out:
            write_json_new(args.out,report)
        print(canonical(report))
        return
    if args.action=='audit':
        root=Path(__file__).parent
        records=[]
        risky={'eval','exec','compile','system','popen','run','Popen','connect','urlopen','request','unlink','remove','replace','rmtree','load','loads','open','write_bytes','write_text'}
        files=list(root.rglob('*.py'))
        for path in files:
            tree=ast.parse(path.read_text(encoding='utf-8'),filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node,ast.Call):
                    target=node.func
                    name=target.id if isinstance(target,ast.Name) else target.attr if isinstance(target,ast.Attribute) else ''
                    if name in risky:
                        records.append({'path':path.relative_to(root).as_posix(),'line':node.lineno,'call':ast.unparse(target)})
        report={'schema':'capture-ast-api-inventory-1','time':utcnow(),'files_parsed':len(files),
                'scope':'wechat_capture_v2 only','not_a_general_purpose_sast':True,'calls_for_manual_review':records}
        if args.out:
            write_json_new(args.out,report)
        print(canonical({'files_parsed':len(files),'calls_for_manual_review':len(records),'syntax_errors':0}))
        return
    if args.action=="marker":
        if not args.state or not args.text or not args.text.startswith('归档测试'):
            parser.error('marker requires state and synthetic test text with approved prefix')
        db=sqlite3.connect((args.state/'catalog.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
        try:
            rows=db.execute("""SELECT first_capture,json_extract(normalized_json,'$.conversation_id'),
                json_extract(normalized_json,'$.direction') FROM version
                WHERE json_extract(normalized_json,'$.body_text')=?""",(args.text,)).fetchall()
            report={"text":args.text,"time":utcnow(),"matches":len(rows),
                "captures":[r[0] for r in rows],"file_transfer_helper":bool(rows) and all(r[1]=='filehelper' for r in rows),
                "outgoing":bool(rows) and all(r[2]=='outgoing' for r in rows)}
            if args.out:
                write_json_new(args.out,report)
            print(canonical(report))
        finally:
            db.close()
        return
    if args.action=="event":
        if not args.state or not args.label:
            parser.error("event requires --state and --label")
        with (args.state/"acceptance-events.private.jsonl").open("a",encoding="utf-8",newline="\n") as stream:
            stream.write(canonical({"time":utcnow(),"label":args.label})+"\n")
        print(canonical({"event_recorded":True,"label":args.label,"time":utcnow()}))
        return
    if args.manifest is None:
        parser.error("manifest required")
    if args.action=="protect":
        files=[{"path":path.relative_to(args.project.resolve()).as_posix(),"bytes":path.stat().st_size,"sha256":digest_file(path)}
               for path in sorted(protected_files(args.project))]
        write_json_new(args.manifest,{"schema":"legacy-preservation-1","created":utcnow(),"files":files})
        print(canonical({"protected_files":len(files),"bytes":sum(row["bytes"] for row in files)}))
    else:
        manifest=json.loads(args.manifest.read_text(encoding="utf-8"))
        failures=[]
        for row in manifest["files"]:
            path=args.project/row["path"]
            if not path.is_file() or path.stat().st_size!=row["bytes"] or digest_file(path)!=row["sha256"]:
                failures.append(row["path"])
        report={"pass":not failures,"checked_files":len(manifest["files"]),"failures":failures,"time":utcnow()}
        if args.out:
            write_json_new(args.out,report)
        print(canonical({"pass":report["pass"],"checked_files":report["checked_files"],"failures":len(failures)}))


if __name__=="__main__":
    main()
