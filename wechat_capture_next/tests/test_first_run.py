"""Portable bootstrap checks; encrypted sources are wholly synthetic."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from wechat_capture_next.first_run import configure
from wechat_capture_next.tests import test_service as fixtures


class FirstRunTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish

    def prepare(self):
        service = fixtures.ServiceTests.init_service(self)
        config = dict(service.config)
        service.close()
        app = self.root / 'portable-app'
        app.mkdir()
        return app, config

    def test_configure_no_capture_no_source_change_and_refuse_overwrite(self):
        app, config = self.prepare()
        before = self.source.read_bytes()
        values = dict(root=app, database_root=config['database_root'], keyring=self.keys,
            account_alias='synthetic-account', source_id='synthetic-source')
        result = configure(**values)
        self.assertTrue(result['configured'])
        state = app / 'archives' / 'wechat-next' / 'state'
        self.assertFalse((state / 'catalog.sqlite').exists())
        self.assertFalse(result['capture_started'])
        self.assertEqual(before, self.source.read_bytes())
        with self.assertRaises(FileExistsError):
            configure(**values)

    def test_invalid_keyring_rejected_before_state_creation(self):
        app, config = self.prepare()
        payload = json.loads(self.keys.read_text(encoding='utf-8'))
        payload['databases'][0]['raw_encryption_key_hex'] = '00'
        self.keys.write_text(json.dumps(payload),encoding='utf-8')
        with self.assertRaises(ValueError):
            configure(app, config['database_root'],self.keys,
                account_alias='synthetic-account',source_id='synthetic-source')
        self.assertFalse((app/'archives'/'wechat-next'/'state').exists())

    def test_arbitrarily_named_keyring_inside_asset_source_is_rejected(self):
        app, config = self.prepare()
        inside=Path(config['database_root']).parent/'ordinary-looking-document.json'
        inside.write_bytes(self.keys.read_bytes())
        with self.assertRaisesRegex(ValueError,'keyring outside'):
            configure(app,config['database_root'],inside,
                account_alias='synthetic-account',source_id='synthetic-source')
        self.assertFalse((app/'archives'/'wechat-next'/'state').exists())

    def test_hardlinked_keyring_cannot_hide_an_alias_inside_asset_source(self):
        import os
        app, config = self.prepare()
        inside=Path(config['database_root']).parent/'ordinary-looking-document.json'
        os.link(self.keys,inside)
        with self.assertRaisesRegex(ValueError,'hardlinked'):
            configure(app,config['database_root'],self.keys,
                account_alias='synthetic-account',source_id='synthetic-source')
        self.assertFalse((app/'archives'/'wechat-next'/'state').exists())

    def test_application_must_not_write_anywhere_inside_live_account(self):
        app, config = self.prepare()
        account = Path(config['database_root']).parent
        before = sorted(str(path.relative_to(account)) for path in account.rglob('*'))
        with self.assertRaisesRegex(ValueError, 'complete source account'):
            configure(account,config['database_root'],self.keys,
                account_alias='synthetic-account',source_id='synthetic-source')
        self.assertEqual(before,sorted(str(path.relative_to(account)) for path in account.rglob('*')))
        self.assertFalse((account/'archives').exists())

    def test_standalone_backup_restore_does_not_require_authors_historical_capsules(self):
        from wechat_capture_next.first_run import default_provenance
        from wechat_capture_next.product import ProductCore
        from wechat_capture_next.tests import test_product as product_fixtures
        app, config = self.prepare()
        configure(app,config['database_root'],self.keys,
            account_alias='synthetic-account',source_id='synthetic-source')
        base=app/'archives'/'wechat-next'
        self.assertIsNone(default_provenance(base/'state',base))
        self.assertEqual(default_provenance(self.root/'state',base),base/'provenance')
        core=ProductCore(base/'state',base/'product',union_root=base/'unified',
            repository_root=base/'backups'/'state',union_repository=base/'backups'/'unified',
            paired_repository=base/'backups'/'paired-v3',provenance_root=None)
        try:
            wait=lambda job=None: product_fixtures.ProductTests.wait(self,core,job)
            wait(core.submit(dict(action='capture',full=True,assets=False)))
            wait(core.submit(dict(action='stop_watch')))
            wait(core.submit(dict(action='deep_verify')))
            result=wait(core.submit(dict(action='backup_pair',include_secrets=True)))
            snapshot=result['result']['snapshot_id']
            restored=wait(core.submit(dict(action='restore_pair',snapshot_id=snapshot,name='restored')))
            self.assertTrue(restored['result']['attachments_closed'])
            restored_config=json.loads((base/'product'/'restored'/'state'/'config.private.json').read_text(encoding='utf-8'))
            self.assertIs(restored_config['standalone_install'],True)
        finally:core.close()

    def test_empty_external_asset_bootstrap_recovers_pending_and_is_idempotent(self):
        from contextlib import closing
        from wechat_capture_next.service import CaptureService
        from wechat_capture_next.union_archive import sync_union
        from wechat_capture_next.compact_archive import CompactArchive
        from wechat_capture_next import union_assets
        app, config = self.prepare()
        configure(app,config['database_root'],self.keys,
            account_alias='synthetic-account',source_id='synthetic-source')
        base=app/'archives'/'wechat-next'
        with closing(CaptureService(base/'state')) as service:
            service.capture(force=True);sync_union(service,base/'unified')
            with CompactArchive(base/'unified'/'archive.wua.sqlite') as archive:
                with patch.object(union_assets,'_catalog_schema',side_effect=RuntimeError('synthetic interrupt')):
                    with self.assertRaises(RuntimeError):union_assets.initialize_standalone_assets(archive,service)
                self.assertEqual(archive._db.execute('SELECT status FROM next_union_asset_receipt').fetchone()[0],'pending')
                union_assets.initialize_standalone_assets(archive,service)
                self.assertTrue(union_assets.verify_union_assets(archive,service)['closure_complete'])
                before=archive._db.total_changes
                union_assets.initialize_standalone_assets(archive,service)
                self.assertEqual(before,archive._db.total_changes)
