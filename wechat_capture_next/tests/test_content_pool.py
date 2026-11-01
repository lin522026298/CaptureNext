import json
from contextlib import closing
import sqlite3
import tempfile
from pathlib import Path
import unittest

from wechat_capture_next.content_pool import ContentPool, register_codec, sql_text_expression, unpack


class ContentPoolTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute('PRAGMA foreign_keys=ON')
        self.pool = ContentPool(self.db, create=True)

    def tearDown(self):
        self.db.close()

    def test_exact_typed_deduplication_and_immutability(self):
        value = '你好\x00"\\\n' * 1000
        identity = self.pool.intern_text(value)
        self.assertEqual(identity, self.pool.intern_text(value))
        self.assertEqual(value, self.pool.get_text(identity))
        binary = bytes(range(256)) * 10
        blob_id = self.pool.intern_bytes(binary)
        self.assertEqual(binary, self.pool.get_bytes(blob_id))
        self.assertNotEqual(self.pool.intern_text(''), self.pool.intern_bytes(b''))
        with self.assertRaises(TypeError):
            self.pool.get_text(blob_id)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('UPDATE content_payload SET data=? WHERE id=?', (b'broken', identity))
        self.assertEqual(4, self.pool.verify()['payloads_verified'])

    def test_canonical_large_leaves_share_body_but_literals_remain_exact(self):
        body = '正文"\\\n🙂' * 500
        body_id = self.pool.intern_text(body)
        text = json.dumps({'body_text': body, 'other': [None, True, False, 0, -0.0, {'unknown': body}]},
                          ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        identity = self.pool.intern_json(text)
        self.assertEqual(text, self.pool.get_text(identity))
        self.assertEqual({body_id}, {r[0] for r in self.db.execute(
            'SELECT atom_id FROM content_payload_reference WHERE payload_id=?', (identity,))})
        sql = 'SELECT ' + sql_text_expression('p') + ' FROM content_payload p WHERE p.id=?'
        self.assertEqual(text, self.db.execute(sql, (identity,)).fetchone()[0])
        self.assertEqual(identity, self.pool.intern_json(text))
        noncanonical = '{ "x":1.00, "x":2, "escaped":"\\u4f60", "unknown": [true,null] }'
        literal_id = self.pool.intern_json(noncanonical)
        self.assertEqual(noncanonical, self.pool.get_text(literal_id))
        self.assertNotEqual('json-recipe-1', self.db.execute(
            'SELECT codec FROM content_payload WHERE id=?', (literal_id,)).fetchone()[0])
        overflow_literal = '{"large_number":1e999,"negative_zero":-0}'
        self.assertEqual(overflow_literal, self.pool.get_text(self.pool.intern_json(overflow_literal)))
        self.pool.verify()

    def test_document_text_used_as_leaf_does_not_create_recursive_recipe(self):
        inner = json.dumps({'body': 'a' * 1000}, sort_keys=True, separators=(',', ':'))
        inner_id = self.pool.intern_json(inner)
        outer = json.dumps({'body': inner}, sort_keys=True, separators=(',', ':'))
        outer_id = self.pool.intern_json(outer)
        self.assertEqual(inner, self.pool.get_text(inner_id))
        self.assertEqual(outer, self.pool.get_text(outer_id))
        self.pool.verify()

    def test_codec_views_resolve_their_own_attached_pool(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ('one', 'two'):
                path = Path(root) / (name + '.sqlite')
                with closing(sqlite3.connect(path)) as db:
                    pool = ContentPool(db, create=True)
                    text = json.dumps({'body': name * 500}, sort_keys=True, separators=(',', ':'))
                    pool.intern_json(text)
                    db.execute('CREATE VIEW decoded AS SELECT id,' + sql_text_expression('p') +
                               ' AS text FROM content_payload p')
                    db.commit()
            with closing(sqlite3.connect(':memory:', uri=True)) as reader:
                register_codec(reader)
                for name in ('one', 'two'):
                    reader.execute(f'ATTACH DATABASE ? AS {name}',
                        ((Path(root)/(name+'.sqlite')).as_uri()+'?mode=ro',))
                    rows = [r[0] for r in reader.execute(f'SELECT text FROM {name}.decoded')]
                    self.assertIn(name * 500, rows)
                    self.assertTrue(any('"body"' in row for row in rows))

    def test_corrupt_content_and_digest_collisions_fail_closed(self):
        with self.assertRaises(ValueError):
            unpack('unknown', b'x', 1)
        with self.assertRaises(ValueError):
            unpack('raw', b'x', 2)
        identity = self.pool.intern_text('original')
        self.db.execute('DROP TRIGGER content_payload_no_update')
        self.db.execute('UPDATE content_payload SET data=? WHERE id=?', (b'altered!', identity))
        with self.assertRaises(ValueError):
            self.pool.intern_text('original')
        with self.assertRaises(ValueError):
            self.pool.verify()


if __name__ == '__main__':
    unittest.main()
