from copy import deepcopy
import unittest
from wechat_capture_next.compact_archive import CompactArchive
from wechat_capture_next import viewer
from tests.test_wua_store import observation


class ViewerTests(unittest.TestCase):
    def archive(self):
        archive=CompactArchive(':memory:');self.addCleanup(archive.close)
        return archive

    def test_long_conversation_context_and_filters(self):
        archive=self.archive()
        rows=[observation(native_locator=i,server_id=str(i+100),body_text='unique-'+str(i),
            event_time='2026-01-01T00:%02d:%02dZ'%(i//60,i%60),sender_id='s'+str(i%2)) for i in range(180)]
        archive.import_observations({'source_id':'a'},{'snapshot_id':'a'},rows)
        selected=viewer.messages(archive,search='unique-99')['rows'][0]
        result=viewer.context(archive,selected['logical_id'])
        self.assertEqual(result['anchor_position'],99)
        self.assertEqual(result['rows'][20]['logical_id'],selected['logical_id'])
        self.assertEqual(viewer.conversations(archive)['rows'][0]['message_count'],180)
        self.assertTrue(all(r['sender_id']=='s1' for r in viewer.messages(archive,sender_id='s1')['rows']))

    def test_detail_preserves_conflict_raw_unknowns_and_not_latest_claim(self):
        archive=self.archive();one=observation(raw_record={'unknown':{'exact':'保留'},'payload':'one'})
        two=deepcopy(one);two['body_text']='edited';two['raw_record']={'unknown':{'exact':'保留'},'payload':'two'}
        archive.import_observations({'source_id':'a'},{'snapshot_id':'a'},[one])
        archive.import_observations({'source_id':'b'},{'snapshot_id':'b'},[two])
        row=archive.list_messages()[0];detail=viewer.detail(archive,row['logical_id'])
        self.assertEqual(len(detail['observations']),2)
        self.assertTrue(detail['conflicts']);self.assertFalse(detail['representative_is_latest'])
        self.assertTrue(all(o['raw_record']['unknown']['exact']=='保留' for o in detail['observations']))

    def test_same_display_name_never_merges_conversations(self):
        archive=self.archive()
        archive.import_observations({'source_id':'a'},{'snapshot_id':'a'},
            [observation(native_locator=i,conversation_id='room'+str(i),server_id=str(i+1)) for i in range(2)])
        archive._db.execute('CREATE TABLE next_viewer_identity(source_id,account_alias,username,name,kind,snapshot_id)')
        archive._db.executemany('INSERT INTO next_viewer_identity VALUES(?,?,?,?,?,?)',
            [('a','synthetic-account','room'+str(i),'same name','remark','evidence') for i in range(2)])
        result=viewer.conversations(archive,search='same name')
        self.assertEqual(len(result['rows']),2)
        self.assertEqual({r['conversation_name'] for r in result['rows']},{'same name'})

    def test_unknown_conversation_context_never_leaks_other_conversations(self):
        archive=self.archive()
        archive.import_observations({'source_id':'a'},{'snapshot_id':'a'},[
            observation(native_locator=1,server_id='1',conversation_id='other-room'),
            observation(native_locator=2,server_id='2',conversation_id=None),
            observation(native_locator=3,server_id='3',conversation_id=None)])
        unknown=[r for r in archive.list_messages() if r['conversation_id'] is None]
        result=viewer.context(archive,unknown[0]['logical_id'])
        self.assertEqual(len(result['rows']),2)
        self.assertTrue(all(r['conversation_id'] is None for r in result['rows']))
        self.assertEqual(len(viewer.messages(archive,null_conversation=True)['rows']),2)

    def test_keys_first_paging_preserves_original_filters_and_nonrepresentative_search(self):
        archive=self.archive()
        rows=[observation(native_locator=i,server_id=str(500+i),body_text='message body '+str(i),
            sender_id='sender'+str(i%2),message_type=str(1+i%2),
            event_time='2026-01-01T00:%02d:%02dZ'%(i//60,i%60)) for i in range(90)]
        archive.import_observations({'source_id':'a'},{'snapshot_id':'a'},rows)
        revised=deepcopy(rows[10]);revised.update(body_text='nonrepresentative searchable revision',raw_record={'revision':True})
        archive.import_observations({'source_id':'b'},{'snapshot_id':'b'},[revised])
        cases=[{},dict(sender_id='sender1'),dict(message_type=2),dict(source_id='b'),dict(snapshot_id='a'),
            dict(since='2026-01-01T00:00:15Z',until='2026-01-01T00:01:10Z'),
            dict(search='searchable'),dict(search='body 1'),dict(search='%'),dict(conflicts_only=True)]
        for filters in cases:
            for offset in (0,5,60):
                with self.subTest(filters=filters,offset=offset):
                    expected=archive.list_messages(limit=7,offset=offset,**filters)
                    actual=viewer.messages(archive,limit=7,offset=offset,**filters)['rows']
                    self.assertEqual([{k:v for k,v in row.items() if k not in ('sender_name','conversation_name')} for row in actual],expected)
        queries=[];archive._db.set_trace_callback(queries.append)
        viewer.messages(archive,limit=7,offset=70)
        archive._db.set_trace_callback(None)
        self.assertTrue(any('SELECT vl.logical_id' in q for q in queries))
        self.assertTrue(any('logical_message WHERE logical_id IN' in q for q in queries))
        self.assertFalse(any(q.startswith('SELECT m.* FROM logical_message') for q in queries))


if __name__=='__main__':unittest.main()
