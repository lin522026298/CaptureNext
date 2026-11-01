import hashlib,importlib.util,random,sqlite3,tempfile,unittest
from contextlib import closing
from pathlib import Path
from tools.wechat_retirement_reader import ChunkReader,ReadOnlyVFS,TreeReader
from wechat_capture_next.pair_repository import Blocks,add_stream

@unittest.skipUnless(importlib.util.find_spec('apsw'),'optional offline audit dependency unavailable')
class RetirementReaderTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  p=Path(self.temp.name)/'source.sqlite'
  with closing(sqlite3.connect(p)) as db:
   db.execute('CREATE TABLE sample(id INTEGER PRIMARY KEY,value BLOB)')
   db.executemany('INSERT INTO sample VALUES(?,?)',[(i,bytes([i%255])*900) for i in range(120)])
   db.commit()
  self.raw=p.read_bytes();self.expected=hashlib.sha256(self.raw).hexdigest()
 def reader(self):
  chunks=[self.raw[i:i+4096] for i in range(0,len(self.raw),4096)]
  return ChunkReader(dict(bytes=len(self.raw),sha256=self.expected,chunks=list(range(len(chunks)))),chunks.__getitem__,4096)
 def test_random_ranges_and_eof(self):
  r=self.reader();rng=random.Random(71)
  for _ in range(200):
   offset=rng.randrange(len(self.raw)+100);size=rng.randrange(0,12000)
   self.assertEqual(r.read(size,offset),self.raw[offset:offset+size].ljust(size,b'\0'))
  self.assertEqual(r.verify()['sha256'],self.expected)
 def test_sqlite_readonly_and_unknown_alias(self):
  import apsw
  v=ReadOnlyVFS({'snapshot':self.reader()});self.addCleanup(v.close)
  db=v.connect('snapshot');self.addCleanup(db.close)
  self.assertEqual(list(db.execute('SELECT count(*),sum(length(value)) FROM sample')),[(120,108000)])
  self.assertEqual(list(db.execute('PRAGMA quick_check')),[('ok',)])
  with self.assertRaises(apsw.ReadOnlyError):db.execute('DELETE FROM sample')
  with self.assertRaises(ValueError):v.connect('unregistered')
  db.execute("ATTACH DATABASE 'file:snapshot?mode=ro' AS old")
  self.assertEqual(list(db.execute('SELECT count(*) FROM old.sample')) ,[(120,)])
 def test_corrupt_boundary_or_digest_refused(self):
  r=self.reader();r.load=lambda key:b'x'
  with self.assertRaises(ValueError):r.read(4,0)
  r=self.reader();r.entry['sha256']='0'*64
  with self.assertRaises(ValueError):r.verify()
 def test_tree_ranges_sqlite_and_complete_digest(self):
  db=sqlite3.connect(':memory:');self.addCleanup(db.close)
  db.executescript('CREATE TABLE block(hash TEXT PRIMARY KEY,kind TEXT,bytes INTEGER,data BLOB);CREATE TABLE edge(parent TEXT,ordinal INTEGER,child TEXT)')
  entry,_=add_stream(db,[self.raw],4096);r=TreeReader(entry,Blocks(db))
  self.assertEqual(r.read(9000,1000),self.raw[1000:10000]);self.assertEqual(r.verify()['sha256'],self.expected)
  v=ReadOnlyVFS({'tree':r});self.addCleanup(v.close);connection=v.connect('tree');self.addCleanup(connection.close)
  self.assertEqual(list(connection.execute('SELECT count(*) FROM sample')),[(120,)])

if __name__=='__main__':unittest.main()
