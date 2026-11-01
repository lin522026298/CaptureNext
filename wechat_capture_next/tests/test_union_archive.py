from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next.union_archive import import_archive,import_catalog,union_path,cold_input
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_next.exports import export_wua


class UnionTests(unittest.TestCase):
    setUp=fixtures.ServiceTests.setUp
    tearDown=fixtures.ServiceTests.tearDown
    pages=fixtures.ServiceTests.pages
    publish=fixtures.ServiceTests.publish
    init_service=fixtures.ServiceTests.init_service

    def test_actual_union_and_catalog_replay_exact(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            legacy=self.root/'readonly-source.sqlite'
            baseline=export_wua(service,legacy)
            source_sha=hashlib.sha256(legacy.read_bytes()).hexdigest()
            target=union_path(self.root/'formal',catalog_instance='unit',create=True)
            with CompactArchive(target,create=True) as archive:
                result=import_archive(archive,legacy,origin_id='frozen-old',verify=True)
                self.assertEqual(result['added_observations'],40)
                self.assertEqual(result['semantic_digest'],baseline['semantic_digest'])
                before=hashlib.sha256(target.read_bytes()).hexdigest()
                with patch.object(archive,'import_legacy_rows',side_effect=AssertionError('replay must not scan rows')):
                    again=import_archive(archive,legacy,origin_id='frozen-old')
                self.assertTrue(again['artifact_reused'])
                self.assertEqual(again['raw_rows_decoded'],0)
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),before)
                current=import_catalog(archive,service.state/'catalog.sqlite',origin_id='live',verify=True)
                self.assertEqual(current['added_observations'],0)
                self.assertEqual(current['added_versions'],40)
                self.assertEqual(current['semantic_digest'],baseline['semantic_digest'])
                before=hashlib.sha256(target.read_bytes()).hexdigest()
                again=import_catalog(archive,service.state/'catalog.sqlite',origin_id='live')
                self.assertEqual(again['added_versions'],0)
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),before)
            self.assertEqual(source_sha,hashlib.sha256(legacy.read_bytes()).hexdigest())

    def test_catalog_failure_rolls_back_and_detaches(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            with CompactArchive(':memory:') as archive:
                original=archive.insert_prepared
                def fail(*args,**kwargs):
                    original(*args,**kwargs)
                    raise RuntimeError('synthetic')
                with patch.object(archive,'insert_prepared',side_effect=fail):
                    with self.assertRaisesRegex(RuntimeError,'synthetic'):
                        import_catalog(archive,service.state/'catalog.sqlite',origin_id='live')
                self.assertEqual(archive.stats()['observations'],0)
                self.assertNotIn('union_catalog',[r[1] for r in archive._db.execute('PRAGMA database_list')])
                self.assertEqual(import_catalog(archive,service.state/'catalog.sqlite',origin_id='live')['added_versions'],40)

    def test_owner_cannot_adopt_or_overlap_old_directory(self):
        target=union_path(self.root/'formal',catalog_instance='unit',create=True)
        self.assertEqual(target.name,'archive.wua.sqlite')
        with self.assertRaises(ValueError):
            union_path(self.root/'formal',catalog_instance='foreign')
        unowned=self.root/'old';unowned.mkdir()
        (unowned/'source.sqlite').write_bytes(b'original')
        with self.assertRaises(FileNotFoundError):
            union_path(unowned,catalog_instance='unit',create=True)

    def test_invalid_origin_refused_before_source_or_target_change(self):
        with CompactArchive(':memory:') as archive:
            before=archive._db.total_changes
            for origin in (None,'',123,'x'*201):
                for method in (import_catalog,import_archive):
                    with self.assertRaises(ValueError):
                        method(archive,self.root/'absent.sqlite',origin_id=origin)
            self.assertEqual(before,archive._db.total_changes)

    def test_requested_deep_verification_failure_rolls_back_import(self):
        with closing(self.init_service()) as service:
            service.capture(force=True)
            source=self.root/'verify-source.sqlite';export_wua(service,source)
            for method,path in ((import_archive,source),(import_catalog,service.state/'catalog.sqlite')):
                with CompactArchive(':memory:') as archive:
                    before=archive.semantic_digest()
                    with patch.object(archive,'integrity_check',side_effect=ValueError('synthetic verification failed')):
                        with self.assertRaisesRegex(ValueError,'verification failed'):
                            method(archive,path,origin_id='verify',verify=True)
                    self.assertEqual(before,archive.semantic_digest())
                    self.assertEqual(archive.stats()['observations'],0)

    @unittest.skipUnless(__import__('os').name=='nt','Windows file share guard')
    def test_cold_guard_denies_write_but_allows_readonly_sql(self):
        source=self.root/'cold.sqlite'
        with closing(sqlite3.connect(source)) as db:
            db.execute('CREATE TABLE sample(v)');db.commit()
        with cold_input(source):
            with self.assertRaises((PermissionError,OSError)):
                source.open('r+b')
            with closing(sqlite3.connect(source.as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM sample').fetchone()[0],0)


if __name__=='__main__':unittest.main()
