"""Process-local exact-cut reuse. Content hashes, not timestamps, are proof.

Only a successful deep operation may seed this cache. Every subsequent check
hashes the complete inventory under Windows deny-write/delete guards. There is
no persistent trust in metadata and no cached claim about current source files.
"""
from contextlib import ExitStack
import hashlib
import os

from .union_archive import cold_input
from wechat_capture_v2.common import digest_file


class ExactCut:
    def __init__(self):
        self.proof = None
        self.result = None

    def fingerprint(self, files, *, expected=None, validator=None):
        files = sorted(set(files), key=str)
        digest = hashlib.sha256()
        total = 0
        with ExitStack() as stack:
            # cold_input is SQLite-specific (sidecar preflight), but works for
            # all ordinary closed files as well. All guards span the whole cut.
            for path in files:
                stack.enter_context(cold_input(path))
            for path in files:
                digest.update(str(path).encode('utf-8'))
                sha = digest_file(path)
                if expected is not None and path in expected and sha != expected[path]:
                    raise ValueError('current bytes differ from the authenticated snapshot cut')
                digest.update(bytes.fromhex(sha))
                total += path.stat().st_size
            if validator is not None:
                validator()
        return digest.hexdigest(), total

    def remember(self, files, result, *, expected, validator=None):
        # No cross-operation reuse without enforceable Windows cold guards.
        self.proof = self.result = None
        if os.name == 'nt':
            self.proof = self.fingerprint(files,expected=expected,validator=validator)[0]
            self.result = result

    def lookup(self, files):
        if self.proof is None or os.name != 'nt':
            return None
        proof, byte_count = self.fingerprint(files)
        if proof != self.proof:
            self.proof = self.result = None
            return None
        return dict(self.result, noop=True, reused_exact_authenticated_cut=True,
            reuse_scope='same_process_exact_content_cut', hashed_bytes=byte_count,
            deep_verification_executed_now=False)


def seal_backup(cache, files, result, state, union, state_repo, union_repo):
    """Bind cached trust to published manifests, authenticate referenced chunks.

    Snapshot IDs come from this successful operation, not a mutable latest row.
    All source/repository file guards span both the hash and validation passes.
    A mutation between backup and sealing fails instead of becoming trusted.
    """
    from contextlib import closing
    from . import backup as sb, union_backup as ub
    state_id=result['state_snapshot']['snapshot_id']
    union_id=result['union_snapshot']['snapshot_id']
    sm=sb.inspect_snapshot(state_repo,state_id)
    um=ub.inspect_snapshot(union_repo,union_id)
    expected={state/name:entry['sha256'] for name,entry in sm['files'].items()}
    actual_state={path for path in files if path.is_relative_to(state)}
    if actual_state != set(expected):
        raise ValueError('current state inventory differs from authenticated snapshot manifest')
    expected[union/'archive.wua.sqlite']=um['archive']['sha256']
    if um['state_companion']['snapshot_id'] != state_id:
        raise ValueError('sealing requires exact paired manifests')

    def validate():
        for module,repository,ident,entries in (
                (sb,state_repo,state_id,list(sm['files'].values())),
                (ub,union_repo,union_id,[um['archive']])):
            _,owner=module._repository(repository)
            with closing(sb._readonly(repository/'repository.sqlite')) as db:
                manifest=module._manifest(db,ident,owner)
                if manifest != (sm if module is sb else um):
                    raise ValueError('snapshot manifest changed before cache sealing')
                for entry in entries:
                    digest=hashlib.sha256();size=0
                    for key in entry['chunks']:
                        block=sb._block(db,key)
                        digest.update(block);size+=len(block)
                    if size != entry['bytes'] or digest.hexdigest() != entry['sha256']:
                        raise ValueError('snapshot referenced bytes failed cache sealing')
    cache.remember(files,result,expected=expected,validator=validate)
