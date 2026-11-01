"""Run the entire next suite with an exact source/test SHA inventory."""
import argparse
import hashlib
from pathlib import Path
import time
import unittest
from wechat_capture_v2.common import write_json_new


def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args(argv)
    if a.out.exists():raise FileExistsError('fresh regression receipt required')
    root=Path(__file__).resolve().parent
    def hashes():
        return {str(path.relative_to(root)).replace('\\','/'):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*.py')) if '__pycache__' not in path.parts}
    before=hashes();started=time.monotonic()
    suite=unittest.defaultTestLoader.discover(str(root/'tests'),top_level_dir=str(root.parent))
    result=unittest.TextTestRunner(verbosity=1).run(suite);after=hashes()
    value=dict(pass_all=result.wasSuccessful() and before==after,tests_run=result.testsRun,
        skipped=len(result.skipped),failures=len(result.failures),errors=len(result.errors),
        elapsed_seconds=time.monotonic()-started,source_hashes_before=before,source_hashes_after=after,
        code_changed_during_run=before!=after,scope='next_suite_not_real_source_coverage')
    write_json_new(a.out,value);return int(not value['pass_all'])


if __name__=='__main__':raise SystemExit(main())
