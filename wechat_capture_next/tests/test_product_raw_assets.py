"""Raw-original listing/export: synthetic metadata, CAS, and no-key restores."""
from contextlib import closing
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wechat_capture_next import raw_assets,product_host
from wechat_capture_next.cas_stream import publish
from wechat_capture_next.service import CaptureService
from wechat_capture_next.tests import test_product as live
from wechat_capture_next.tests import test_recovery_core as offline
from wechat_capture_v2.common import digest_file
from wechat_capture_v2.objects import Objects


class RawAssetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.output=tempfile.TemporaryDirectory();self.addCleanup(self.output.cleanup)
        self.root=Path(self.temp.name);self.target=Path(self.output.name)/'original.bin'
        self.catalog=sqlite3.connect(self.root/'catalog.sqlite');self.addCleanup(self.catalog.close)
        self.archive=SimpleNamespace(_db=sqlite3.connect(self.root/'archive.sqlite'))
        self.addCleanup(self.archive._db.close)
        self.objects=Objects(self.root/'objects.sqlite');self.addCleanup(self.objects.close)
        self.catalog.execute('CREATE TABLE asset_history(source_id,relative_path,file_sha,bytes,cycle_id)')
        self.archive._db.execute('''CREATE TABLE next_union_asset_observation(observation_id,origin_id,
            source_table,source_id,relative_path,file_sha,bytes)''')
        self.data=b'raw-only-no-message-association\x00\xff'*30000
        self.sha=publish(self.objects,io.BytesIO(self.data),len(self.data))['sha256']
        self.catalog.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',
            ('current','raw/current.bin',self.sha,len(self.data),'current-cycle'))
        self.archive._db.executemany('INSERT INTO next_union_asset_observation VALUES(?,?,?,?,?,?,?)',[
            (str(i),'external-origin','asset_history','oldPC','raw/history-'+str(i)+'.bin',self.sha,len(self.data))
            for i in range(12)])
        self.catalog.commit();self.archive._db.commit()

    def listing(self,**kwargs):
        return raw_assets.listing(self.archive,self.catalog,self.objects.db,**kwargs)

    def export(self,**kwargs):
        return raw_assets.export(self.archive,self.catalog,self.objects.db,sha=self.sha,
            destination=kwargs.pop('destination',self.target),protected_roots=[self.root],**kwargs)

    def test_all_history_content_and_all_provenance_paginate_without_association(self):
        other=publish(self.objects,io.BytesIO(b'other historical original'),25)['sha256']
        self.catalog.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',('earlier','old/not-current.bin',other,25,'earlier-cycle'))
        self.catalog.commit()
        first=self.listing(limit=1);second=self.listing(limit=1,offset=first['next_offset'])
        self.assertEqual({row['file_sha'] for row in first['rows']+second['rows']},{self.sha,other})
        self.assertEqual(first['total'],2);self.assertIsNone(second['next_offset'])
        selected=next(row for row in self.listing()['rows'] if row['file_sha']==self.sha)
        self.assertEqual(selected['evidence_count'],13);self.assertEqual(len(selected['evidence']),8)
        self.assertTrue(selected['evidence_examples_truncated'])
        self.assertEqual(selected['message_association'],'unknown');self.assertFalse(selected['origin_link_confirmed'])
        self.assertFalse(selected['sha256_original_bytes_verified'])
        rows=[];offset=0
        while True:
            page=raw_assets.evidence_page(self.archive,self.catalog,self.sha,limit=3,offset=offset)
            rows.extend(page['rows'])
            if page['next_offset'] is None:break
            offset=page['next_offset']
        self.assertEqual(len(rows),13)
        self.assertEqual(len({row['relative_path'] for row in rows}),13)
        self.assertEqual({row['scope'] for row in rows},{'retained_union','current_state_history'})

    def test_stream_export_authenticates_full_original_and_independent_readback_without_db_writes(self):
        before=[db.total_changes for db in (self.catalog,self.archive._db,self.objects.db)]
        result=self.export()
        self.assertEqual(self.target.read_bytes(),self.data)
        self.assertTrue(result['sha256_original_bytes_verified']);self.assertTrue(result['export_readback_verified'])
        self.assertEqual(result['message_association'],'unknown');self.assertFalse(result['automatically_opened'])
        self.assertEqual(before,[db.total_changes for db in (self.catalog,self.archive._db,self.objects.db)])
        with self.assertRaises(FileExistsError):self.export()
        self.assertEqual(digest_file(self.target),self.sha)
        with self.assertRaisesRegex(ValueError,'protected'):self.export(destination=self.root/'forbidden.bin')
        self.assertFalse((self.root/'forbidden.bin').exists())

    def test_missing_unproven_and_corrupt_objects_never_become_success(self):
        absent='a'*64
        self.catalog.execute('INSERT INTO asset_history VALUES(?,?,?,?,?)',('old','missing.bin',absent,1,'old'))
        self.catalog.commit()
        missing=next(row for row in self.listing()['rows'] if row['file_sha']==absent)
        self.assertFalse(missing['available_in_cas']);self.assertEqual(missing['status'],'file_missing')
        with self.assertRaises(FileNotFoundError):
            raw_assets.export(self.archive,self.catalog,self.objects.db,sha=absent,destination=self.target,protected_roots=[self.root])
        with self.assertRaisesRegex(ValueError,'provenance'):
            raw_assets.export(self.archive,self.catalog,self.objects.db,sha='b'*64,destination=self.target,protected_roots=[self.root])
        self.objects.db.execute("UPDATE chunk SET data=x'00'");self.objects.db.commit()
        with self.assertRaises(Exception):self.export()
        self.assertFalse(self.target.exists())

    def test_corrupt_output_readback_is_failure_and_removes_only_fresh_output(self):
        original=Path.open
        def changed(path,mode='r',*args,**kwargs):
            if path==self.target and mode=='rb':return io.BytesIO(b'corrupt output readback')
            return original(path,mode,*args,**kwargs)
        with patch.object(Path,'open',changed):
            with self.assertRaisesRegex(ValueError,'readback'):self.export()
        self.assertFalse(self.target.exists())

    def test_existing_hardlink_is_not_written_or_removed(self):
        original=Path(self.output.name)/'incumbent.bin';original.write_bytes(b'original incumbent')
        os.link(original,self.target)
        with self.assertRaises((FileExistsError,ValueError)):self.export()
        self.assertEqual(original.read_bytes(),b'original incumbent')
        self.assertEqual(self.target.read_bytes(),b'original incumbent')

    @unittest.skipUnless(os.name=='nt','Windows directory junction check')
    def test_junction_output_is_rejected_before_creating_a_file(self):
        junction=Path(self.output.name)/'junction'
        subprocess.run(['cmd','/c','mklink','/J',str(junction),str(self.root)],check=True,capture_output=True)
        self.addCleanup(lambda:os.rmdir(junction))
        with self.assertRaisesRegex(ValueError,'links/reparse'):
            self.export(destination=junction/'forbidden.bin')
        self.assertFalse((self.root/'forbidden.bin').exists())


class LiveRawAssetTests(unittest.TestCase):
    setUp=live.ProductTests.setUp
    tearDown=live.ProductTests.tearDown
    pages=live.ProductTests.pages
    publish=live.ProductTests.publish
    init_service=live.ProductTests.init_service
    prepared=live.ProductTests.prepared
    core=live.ProductTests.core
    wait=live.ProductTests.wait

    def test_current_product_lists_retained_external_original_and_exports_without_message_selection(self):
        core=self.core()
        result=product_host.product_read(core,'/api/assets',dict(view=['current']))
        selected=next(row for row in result['rows'] if row['file_sha']==self.file_sha)
        self.assertTrue(selected['available_in_cas']);self.assertGreater(selected['evidence_count'],0)
        provenance=product_host.product_read(core,'/api/assets',dict(view=['current'],id=[self.file_sha],limit=['1']))
        self.assertEqual(len(provenance['rows']),1)
        job=self.wait(core,core.submit(dict(action='export_raw_asset',sha=self.file_sha,name='current-original.dat',view='current')))
        self.assertTrue(job['result']['export_readback_verified'])
        self.assertEqual((core.output_root/'current-original.dat').read_bytes(),self.payload)
        for name in ('../no.bin','bad/name','CON'):
            with self.assertRaises(ValueError):core.submit(dict(action='export_raw_asset',sha=self.file_sha,name=name))


class OfflineRawAssetTests(unittest.TestCase):
    setUp=offline.RecoveryTests.setUp
    tearDown=offline.RecoveryTests.tearDown
    pages=offline.RecoveryTests.pages
    publish=offline.RecoveryTests.publish
    init_service=offline.RecoveryTests.init_service
    prepared=offline.RecoveryTests.prepared
    setup_copy=offline.RecoveryTests.setup_copy
    take_source_offline=offline.RecoveryTests.take_source_offline
    core=offline.RecoveryTests.core
    wait=offline.RecoveryTests.wait

    def test_no_keys_no_source_restore_lists_and_exports_original_without_any_restored_mutation(self):
        self.setup_copy();self.take_source_offline()
        before={str(path):digest_file(path) for path in self.restored.rglob('*') if path.is_file()}
        with patch.object(CaptureService,'__init__',side_effect=AssertionError('no live service or login')):
            core=self.core()
            self.wait(core,core.submit(dict(action='open_restored',path=str(self.restored))))
            response=product_host.product_read(core,'/api/assets',dict(view=['restored']))
            self.assertEqual(response['rows'][0]['file_sha'],self.file_sha)
            self.assertEqual(response['rows'][0]['message_association'],'unknown')
            job=self.wait(core,core.submit(dict(action='export_raw_asset',view='restored',sha=self.file_sha,name='offline-original.dat')))
            self.assertTrue(job['result']['export_readback_verified'])
            self.assertEqual((core.output_root/'offline-original.dat').read_bytes(),self.payload)
            with self.assertRaises(ValueError):product_host.product_read(core,'/api/assets',dict(view=['current']))
            with self.assertRaises(ValueError):core.submit(dict(action='export_raw_asset',view='current',sha=self.file_sha,name='forbidden.dat'))
        self.assertEqual(before,{str(path):digest_file(path) for path in self.restored.rglob('*') if path.is_file()})
        self.assertFalse(self.source.parent.exists())


if __name__=='__main__':unittest.main()
