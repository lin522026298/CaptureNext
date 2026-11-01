from pathlib import Path
import unittest
from wechat_capture_next.tests import test_assets as fixtures
from wechat_capture_next import assets


class ExternalReferenceTests(unittest.TestCase):
    setUp=fixtures.AssetTests.setUp
    tearDown=fixtures.AssetTests.tearDown

    def pin(self):
        db=self.service.catalog.db
        path=self.root/'external';path.write_bytes(b'old unique content')
        obj=self.service.objects.add(path)
        owner='0123456789abcdef0123456789abcdef'
        with db:
            db.execute("INSERT INTO meta VALUES('next_catalog_instance','test-instance')")
            db.execute('CREATE TABLE external_asset_owner(owner_id TEXT PRIMARY KEY,cas_id TEXT,schema TEXT)')
            db.execute('CREATE TABLE external_asset_ref(owner_id TEXT,file_sha TEXT,bytes INTEGER,cas_id TEXT,PRIMARY KEY(owner_id,file_sha))')
            db.execute('INSERT INTO external_asset_owner VALUES(?,?,?)',(owner,'capture-next-objects:test-instance','next-union-assets-1'))
            db.execute('INSERT INTO external_asset_ref VALUES(?,?,?,?)',(owner,obj['sha256'],obj['bytes'],'capture-next-objects:test-instance'))
        return owner,obj

    def test_external_objects_verified_without_faking_current_cycles(self):
        owner,obj=self.pin()
        proof=assets.verify_assets(self.service)
        self.assertEqual(proof['external_asset_references_verified'],1)
        self.assertEqual(proof['files_verified'],1)
        self.assertEqual(proof['asset_references_verified'],0)
        self.assertEqual(proof['referenced_asset_objects_verified'],1)
        self.assertEqual(assets.prune_unpublished(self.service)['published_files_removed'],0)
        self.assertEqual(assets.verify_assets(self.service)['external_asset_references_verified'],1)
        exported=self.root/'new-external.raw'
        assets.export_asset(self.service,obj['sha256'],exported)
        self.assertEqual(exported.read_bytes(),b'old unique content')

    def test_missing_external_object_and_identity_mismatch_fail_closed(self):
        owner,obj=self.pin()
        db=self.service.catalog.db
        with db:db.execute('UPDATE external_asset_ref SET bytes=bytes+1')
        with self.assertRaisesRegex(ValueError,'external asset'):
            assets.verify_assets(self.service,verify_objects=False)
        with db:
            db.execute('UPDATE external_asset_ref SET bytes=?',(obj['bytes'],))
            db.execute("UPDATE external_asset_owner SET cas_id='wrong'")
        with self.assertRaisesRegex(ValueError,'owner binding'):
            assets.verify_assets(self.service,verify_objects=False)


if __name__=='__main__':unittest.main()
