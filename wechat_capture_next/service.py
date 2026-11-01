"""Small-scope changed-write backend, in a new explicit state only.

Uses the frozen v2 row interpretation, complete scans, immutable versions and
transactional checkpoint implementation unchanged. Raw intermediate database
generations are not retained; one current decoded view is final usable data.
"""
import hashlib
import json
from pathlib import Path
import time
import uuid

from wechat_capture_v2.common import canonical, digest_file, utcnow, write_json_new
from wechat_capture_v2.service import CaptureService as PreviousService, initialize as previous_initialize
from .materialize import update_view
from .catalog import Catalog, FORMAT, assert_supported

MODE = 'capture-next-final-views-1'


def initialize(state, *args, **kwargs):
    from .paths import local_absolute
    state = local_absolute(state, allow_relative=True)
    config = previous_initialize(state, *args, **kwargs)
    write_json_new(Path(state)/'next.private.json', {'schema': MODE,
        'evidence_storage': FORMAT,
        'raw_ciphertext_generations_retained': False,
        'retention': 'one_current_decoded_view_and_all_observed_message_versions'})
    return config


class CaptureService(PreviousService):
    def __init__(self, state):
        from .state_guard import state_preflight
        state = state_preflight(state)
        marker = json.loads((state/'next.private.json').read_text(encoding='utf-8'))
        if marker.get('schema') != MODE:
            raise ValueError('explicit new next state required; never upgrade an existing archive')
        if marker.get('evidence_storage') not in (None, FORMAT):
            raise ValueError('unsupported requested evidence storage')
        if any((state/name).exists() for name in ('RESTORE.partial.private.json', 'RESTORE.failure.private.json')):
            raise ValueError('incomplete restored state cannot be opened for capture; restore to a fresh directory')
        assert_supported(state/'catalog.sqlite')
        from .assets import recover_asset_configuration
        recover_asset_configuration(state)
        fresh_catalog = not (state/'catalog.sqlite').exists()
        super().__init__(state)
        # The inherited constructor performs the unchanged source/key binding
        # checks. Reopen ONLY the next state's catalog with the write adapter.
        self.catalog.close()
        self.catalog = Catalog(state/'catalog.sqlite')
        if fresh_catalog or marker.get('evidence_storage') == FORMAT:
            self.catalog.enable_compact()
        self._binding_cache = {}
        self._binding_cache_version = None
        # scan_seen/scan_tables are short-lived reconciliation working sets,
        # not recovery data. Keep them out of SQLite's temporary disk files.
        self.catalog.db.execute('PRAGMA temp_store=MEMORY')
        # Physical view compatibility depends on the decoder/WAL/profile/key,
        # not on report storage or UI changes. Keep row-interpretation binding
        # separate: changing a reader still forces complete reconciliation.
        from wechat_capture_v2 import cipher as cipher_module
        self.view_binding = hashlib.sha256(canonical(dict(
            materializer=digest_file(Path(__file__).with_name('materialize.py')),
            wal=digest_file(Path(__file__).with_name('wal_memory.py')),
            cipher=digest_file(cipher_module.__file__), profile='weixin4-4096-reserve80-raw32')).encode()).hexdigest()
        self.interpretation_binding = hashlib.sha256((self.interpretation_binding +
            digest_file(Path(__file__).with_name('materialize.py')) +
            digest_file(Path(__file__).with_name('wal_memory.py')) + digest_file(__file__) + MODE).encode()).hexdigest()

    def view_path(self, relative):
        return self.state/'cache'/(hashlib.sha256(relative.encode()).hexdigest()+'.db')

    def validate_output(self, path):
        from .paths import local_absolute
        output = local_absolute(path, allow_relative=True)
        roots = [self.state, local_absolute(self.config['database_root']).parent]
        if self.config.get('asset_root'):
            roots.append(local_absolute(self.config['asset_root']))
        if any(output.is_relative_to(root) or root.is_relative_to(output) for root in roots):
            raise ValueError('output overlaps a state or the bound live account tree')
        if output.exists():
            raise FileExistsError('a fresh output is required; existing deliverables are never overwritten')
        return output

    def capture_assets(self, cycle, force=False, budget_seconds=None, verify_shared=False):
        from .assets import capture_assets
        result = capture_assets(self, cycle, force, budget_seconds, verify_shared)
        batch = getattr(self,'_asset_batch',None)
        if batch is not None and cycle != batch['cycle_id'] and result.get('complete'):
            self.finish_asset_progress('local_complete' if not result['errors'] else 'partial',
                                       completion_cycle=cycle,completion_assets=result)
        return result

    def needs_reconcile(self, relative, current_stamp):
        previous = self.catalog.checkpoint(self.config['source_id'], relative)
        view = self.view_path(relative)
        if (not previous or previous['stamp_json'] != canonical(current_stamp) or not view.is_file()
                or view.with_suffix('.dirty').exists() or view.with_suffix('.pending').exists()
                or not view.with_suffix('.pages.sqlite').is_file()):
            return True
        # Cache only the immutable binding lookup, not source stamps, inventory,
        # dirty/pending markers, or the periodic cryptographic verification.
        # One entry per relative path; accepted capture IDs invalidate it.
        version = (self.catalog.db.total_changes, self.catalog.db.execute('PRAGMA data_version').fetchone()[0])
        if self._binding_cache_version != version:
            self._binding_cache.clear()
            self._binding_cache_version = version
        cached = self._binding_cache.get(relative)
        if not cached or cached[0] != previous['capture_id']:
            evidence = self.catalog.db.execute('SELECT evidence_json FROM db_capture WHERE id=?',
                (previous['capture_id'],)).fetchone()
            cached = (previous['capture_id'], json.loads(evidence[0]).get('interpretation_binding') if evidence else None)
            self._binding_cache[relative] = cached
        return cached[1] != self.interpretation_binding

    def capture(self, *, force=False, assets=False, retries=3, asset_budget_seconds=None, reuse_identical=False,
                asset_force=None):
        if retries < 1:
            raise ValueError('positive retries required')
        if asset_force is not None and type(asset_force) is not bool:
            raise ValueError('asset_force must be a boolean or None')
        began = time.monotonic()
        inventory_error = None
        try:
            inventory = self.databases()
            stamps = {relative: self._stamp(path) for relative, path in inventory.items()}
        except (OSError, ValueError) as exc:
            inventory, stamps = {}, {}
            inventory_error = type(exc).__name__
        known = {r[0] for r in self.catalog.db.execute('SELECT relative_path FROM checkpoint WHERE source_id=?',
            (self.config['source_id'],))}
        if assets and not force:
            from .assets import assets_need_scan
            try:
                assets = assets_need_scan(self)
            except (OSError, ValueError):
                pass  # Keep the normal partial/error path, never label it idle.
        source_unchanged = bool(inventory and known == set(inventory) and all(
            not self.needs_reconcile(r, stamps[r]) for r in inventory))
        if not force and not assets and source_unchanged:
            return dict(status='idle', elapsed_seconds=time.monotonic()-began, databases=[], errors=[],
                summary=self._summary_cache, cycle_id=None, mode='metadata_poll')
        if not force and assets and source_unchanged:
            return self._asset_only_poll(began,asset_budget_seconds)
        cycle = self.catalog.begin_cycle('full_reconciliation' if force else 'changed_shards')
        report = dict(schema='capture-next-cycle-1', cycle_id=cycle, started=utcnow(), status='running',
            mode='full_reconciliation' if force else 'changed_shards', databases=[], errors=[],
            message_count_limit=None, history_time_limit=None, intermediate_commit_history=False)
        try:
            if not inventory:
                report['errors'].append({'error_type': inventory_error or 'source_empty_or_unavailable', 'checkpoint_advanced': False})
            for relative, path in sorted(inventory.items()):
                previous = self.catalog.checkpoint(self.config['source_id'], relative)
                if not force and not self.needs_reconcile(relative, stamps[relative]):
                    report['databases'].append({'relative_path': relative, 'status': 'unchanged_metadata'})
                    continue
                if relative not in self.keys:
                    report['errors'].append({'relative_path': relative, 'error_type': 'missing_key', 'checkpoint_advanced': False})
                    continue
                for attempt in range(retries):
                    try:
                        view = self.view_path(relative)
                        pending = view.with_suffix('.pending')
                        if not pending.exists():
                            write_json_new(pending, {'state': 'view_not_yet_accepted_by_catalog'})
                        auth = update_view(path, view, self.keys[relative], scratch=self.state/'tmp',
                            binding=self.view_binding)
                        plain = {'sha256': auth['plaintext_sha256'], 'bytes': view.stat().st_size,
                                 'storage': 'current_decoded_view_not_historical_object'}
                        evidence = dict(plaintext=plain, authentication=auth, source_read_only=True,
                            interpretation_binding=self.interpretation_binding, origin='live_files_changed_write',
                            time=utcnow(), retention='final_view_and_observed_rows_no_raw_generations',
                            scan_plan={'tables': None, 'reason': 'complete_row_reconciliation'})
                        prior = self.catalog.db.execute('SELECT evidence_json,message_count FROM db_capture WHERE id=?',
                            (previous['capture_id'],)).fetchone() if previous else None
                        old_evidence = json.loads(prior['evidence_json']) if prior else {}
                        same_rows = ((not force or reuse_identical) and auth['structured_readable']
                            and old_evidence.get('authentication', {}).get('structured_readable')
                            and old_evidence.get('interpretation_binding') == self.interpretation_binding
                            and old_evidence.get('plaintext', {}).get('sha256') == plain['sha256'])
                        if same_rows:
                            evidence['reader'] = old_evidence['reader']
                            evidence['row_scan_reused_from'] = previous['capture_id']
                            ident = uuid.uuid4().hex
                            with self.catalog.db:
                                self.catalog.db.execute('INSERT INTO db_capture VALUES(?,?,?,?,?,?,?,?)',
                                    (ident, cycle, self.config['source_id'], relative, auth['signature'],
                                     canonical(evidence), prior['message_count'], utcnow()))
                                self.catalog.db.execute('''UPDATE checkpoint SET capture_id=?,signature=?,stamp_json=?
                                    WHERE source_id=? AND relative_path=?''',
                                    (ident, auth['signature'], canonical(stamps[relative]), self.config['source_id'], relative))
                            result = dict(capture_id=ident, rows=0, new_versions=0, verified_identical_decoded_rows_reused=True)
                        elif auth['structured_readable']:
                            result = self.catalog.ingest(cycle=cycle, source_id=self.config['source_id'],
                                account=self.config['account_alias'], relative=relative, path=view, evidence=evidence,
                                signature=auth['signature'], stamp_value=stamps[relative],
                                self_username=self.config.get('self_username'))
                        else:
                            if Path(relative).parent.name == 'message' and not Path(relative).stem.endswith('_fts'):
                                raise ValueError('message shard has no supported structured reader')
                            result = self.catalog.raw_only(cycle=cycle, source_id=self.config['source_id'],
                                relative=relative, evidence=evidence, signature=auth['signature'], stamp_value=stamps[relative])
                        try:
                            pending.unlink()
                        except OSError:
                            result['optional_pending_cleanup_warning'] = True
                        report['databases'].append(dict(relative_path=relative, status='accepted',
                            changed_plain_pages=auth['changed_plain_pages'], decrypted_pages=auth['decrypted_pages'],
                            frozen_wal_bytes=auth['frozen_wal_bytes'], memory_wal_bytes=auth['memory_wal_bytes'],
                            main_copy_bytes=0, temporary_wal_bytes=auth['temporary_wal_bytes'], **result))
                        break
                    except Exception as exc:
                        if attempt+1 == retries:
                            report['errors'].append(dict(relative_path=relative, error_type=type(exc).__name__,
                                detail_private=str(exc), checkpoint_advanced=False))
            try:
                after_inventory = set(self.databases())
            except (OSError, ValueError):
                after_inventory = None
            if after_inventory != set(inventory) or known-set(inventory):
                report['errors'].append({'error_type': 'source_inventory_changed_or_missing', 'checkpoint_advanced': False})
            if assets:
                report['assets'] = self.capture_assets(cycle, force=force if asset_force is None else asset_force,
                    budget_seconds=asset_budget_seconds, verify_shared=bool(force and asset_force is False))
                report['errors'].extend(report['assets']['errors'])
            report['status'] = 'partial' if report['errors'] else 'local_complete'
            if report['status'] == 'local_complete' and assets and not report['assets'].get('complete', True):
                report['status'] = 'local_complete_assets_pending'
        except Exception as exc:
            report['status'] = 'partial'
            report['errors'].append(dict(error_type=type(exc).__name__, detail_private=str(exc), checkpoint_advanced=False))
        except BaseException:
            report['status'] = 'interrupted'
            raise
        finally:
            report['finished'] = utcnow()
            report['elapsed_seconds'] = time.monotonic()-began
            report['summary'] = self.catalog.summary(ignore_cycle=cycle)
            self._summary_cache = report['summary']
            self.catalog.finish_cycle(cycle, report)
            # One authoritative full report in cycle.report_json. Historical
            # report files remain untouched; callers may explicitly export it.
        return report

    def _asset_only_poll(self, began, budget):
        """Persist one continuation report, not one large report per slice.

        Accepted per-file history still references this durable cycle. A crash
        marks it interrupted; incomplete source progress is never an idle proof.
        """
        if getattr(self,'_asset_batch',None) is None:
            self._asset_batch = dict(cycle_id=self.catalog.begin_cycle('asset_continuation'),
                started=utcnow(), rounds=0, new_versions=0, file_visits=0, verified_unchanged_bytes=0)
        batch = self._asset_batch
        try:
            result = self.capture_assets(batch['cycle_id'],budget_seconds=budget)
            batch['rounds'] += 1
            batch['new_versions'] += result.get('new_versions',0)
            batch['file_visits'] += result.get('files_seen',0)
            batch['verified_unchanged_bytes'] += result.get('verified_unchanged_bytes',0)
            batch['last_assets'] = result
            status = 'partial' if result.get('errors') else (
                'local_complete' if result.get('complete') else 'local_complete_assets_pending')
            self._summary_cache = self.catalog.summary(ignore_cycle=batch['cycle_id'])
            report = dict(schema='capture-next-cycle-1',cycle_id=batch['cycle_id'],started=batch['started'],
                status=status,mode='asset_continuation',databases=[],assets=result,errors=result['errors'],
                elapsed_seconds=time.monotonic()-began,summary=self._summary_cache,
                durable_progress='one_report_per_continuation_batch',history_time_limit=None,message_count_limit=None)
            if result.get('complete') or result.get('errors'):
                self.finish_asset_progress(status)
            return report
        except BaseException:
            self.finish_asset_progress('interrupted')
            raise

    def finish_asset_progress(self,status='interrupted',**details):
        batch = getattr(self,'_asset_batch',None)
        if batch is not None:
            completed_assets = details.pop('completion_assets',batch.get('last_assets'))
            report = dict(schema='capture-next-cycle-1',**batch,status=status,
                mode='asset_continuation',finished=utcnow(),databases=[],
                assets=completed_assets,errors=(completed_assets or {}).get('errors',[]),
                summary=self.catalog.summary(ignore_cycle=batch['cycle_id']),
                coverage='accepted per-file observations; continuation aggregate, not a new source cut',**details)
            self.catalog.finish_cycle(batch['cycle_id'],report)
            self._asset_batch = None

    def close(self):
        observer = getattr(self, '_asset_notifications', None)
        try:
            self.finish_asset_progress('interrupted',reason='service_closed_at_safe_boundary')
            if observer is not None:
                observer.close()
                self._asset_notifications = None
        finally:
            super().close()

    def verify_state(self):
        if [r[0] for r in self.catalog.db.execute('PRAGMA quick_check')] != ['ok']:
            raise ValueError('catalog integrity failed')
        if list(self.catalog.db.execute('PRAGMA foreign_key_check')):
            raise ValueError('catalog foreign keys failed')
        self.catalog.verify_templates()
        reports_verified = self.catalog.verify_reports()
        count = 0
        for relative, evidence_json in self.catalog.db.execute('''SELECT c.relative_path,d.evidence_json
            FROM checkpoint c JOIN db_capture d ON d.id=c.capture_id WHERE c.source_id=?''',
            (self.config['source_id'],)):
            view = self.view_path(relative)
            if (view.with_suffix('.dirty').exists() or view.with_suffix('.pending').exists()
                    or digest_file(view) != json.loads(evidence_json)['plaintext']['sha256']):
                raise ValueError('current decoded view not at accepted checkpoint; run reconciliation')
            count += 1
        from .assets import verify_assets
        result = verify_assets(self)
        # The frozen asset schema stores cycle text without a SQL FK. Verify
        # logical provenance explicitly rather than claiming the FK does it.
        asset_cycles = 0
        for table in ('asset','asset_history'):
            if self.catalog.db.execute(f'''SELECT 1 FROM {table} a LEFT JOIN cycle c
                ON c.id=a.cycle_id WHERE c.id IS NULL LIMIT 1''').fetchone():
                raise ValueError('attachment provenance cycle is missing')
            asset_cycles += self.catalog.db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
        return dict(**result, current_views_verified=count, reports_verified=reports_verified,
                    attachment_provenance_cycles_verified=asset_cycles,historical_ciphertext_recoverable=False)
