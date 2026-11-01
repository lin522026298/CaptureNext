import unittest
from wechat_capture_next import viewer,viewer_access
from wechat_capture_next.compact_archive import CompactArchive
from tests.test_wua_store import observation


class AccessTests(unittest.TestCase):
    def test_single_transaction_index_keeps_messages_and_provenance_identical(self):
        archive=CompactArchive(':memory:');self.addCleanup(archive.close)
        archive.import_observations({'source_id':'a'},{'snapshot_id':'a'},[
            observation(native_locator=i,server_id=str(100+i),sender_id='s'+str(i%2),
                body_text='synthetic '+str(i),event_time='2026-01-01T00:00:%02dZ'%i) for i in range(40)])
        before=archive.semantic_digest();messages=viewer.messages(archive,offset=12,limit=7)
        conv=viewer.conversations(archive);context=viewer.context(archive,messages['rows'][3]['logical_id'])
        self.assertTrue(viewer_access.ensure(archive)['created'])
        self.assertFalse(viewer_access.ensure(archive)['created'])
        self.assertEqual(archive.semantic_digest(),before)
        self.assertEqual(viewer.messages(archive,offset=12,limit=7),messages)
        self.assertEqual(viewer.conversations(archive),conv)
        self.assertEqual(viewer.context(archive,messages['rows'][3]['logical_id']),context)
        self.assertEqual(viewer.messages(archive,search='synthetic 19')['rows'][0]['body_text'],'synthetic 19')

    def test_foreign_index_name_is_not_silently_trusted(self):
        archive=CompactArchive(':memory:');self.addCleanup(archive.close)
        archive._db.execute('CREATE INDEX '+viewer_access.INDEX+' ON logical_record(logical_id)')
        with self.assertRaisesRegex(ValueError,'unexpected'):viewer_access.ensure(archive)
        with self.assertRaisesRegex(ValueError,'unexpected'):viewer.messages(archive)

    def test_reader_does_not_migrate_old_copies(self):
        archive=CompactArchive(':memory:');self.addCleanup(archive.close);archive.readonly=True
        self.assertFalse(viewer_access.present(archive))
        self.assertEqual(viewer.messages(archive)['rows'],[])
        with self.assertRaisesRegex(ValueError,'owned writer'):viewer_access.ensure(archive)


if __name__=='__main__':unittest.main()
