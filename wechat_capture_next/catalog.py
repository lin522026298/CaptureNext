"""Lossless evidence templates, with a native-SQL readable compatibility view.

Only the two top-level per-observation slots are factored out. Templates are
shared ONLY by exact text equality, never by a source signature or row count.
The original table is renamed, so SQLite redirects existing child FKs to the
real entity table rather than to a view. No message/version table is rebuilt.
Existing catalogs are not migrated merely by opening them.
"""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sqlite3
from contextlib import closing

from wechat_capture_v2.common import canonical
from wechat_capture_v2.store import Catalog as PreviousCatalog

FORMAT = 'exact-evidence-templates-1'
TIME = '\x1etime\x1e'
REUSE = '\x1ereuse\x1e'


def assert_supported(path):
    path = Path(path)
    if not path.exists():
        return
    # Refuse future/incomplete extensions before any inherited startup writes.
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").fetchone():
            return  # A crash immediately after connect may leave a zero-schema DB.
        row = db.execute("SELECT value FROM meta WHERE key='next_evidence_storage'").fetchone()
        if row:
            if row[0] != FORMAT:
                raise ValueError('unsupported evidence storage format')
            objects = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name IN('db_capture','capture_record','evidence_template','capture_insert','capture_update','accepted_capture_no_update','capture_no_delete','template_no_update')"))
            if objects != {'db_capture': 'view', 'capture_record': 'table', 'evidence_template': 'table',
                           'capture_insert': 'trigger', 'capture_update': 'trigger',
                           'accepted_capture_no_update': 'trigger', 'capture_no_delete': 'trigger',
                           'template_no_update': 'trigger'}:
                raise ValueError('incomplete evidence storage extension')


@lru_cache(maxsize=16)
def pack(text):
    value = json.loads(text)
    slots = {}
    template = text
    # Historical/noncanonical valid JSON is kept verbatim, without factoring.
    if isinstance(value, dict) and canonical(value) == text:
        parts = []
        for key in sorted(value):
            encoded = canonical(value[key])
            if key in ('time', 'row_scan_reused_from'):
                slot, marker = ('t', TIME) if key == 'time' else ('r', REUSE)
                slots[slot] = encoded
                encoded = marker
            parts.append(canonical(key)+':'+encoded)
        template = '{'+','.join(parts)+'}'
    restored = template.replace(TIME, slots.get('t', '')).replace(REUSE, slots.get('r', ''))
    if restored != text:
        raise ValueError('evidence factoring was not byte exact')
    return template, canonical(slots), hashlib.sha256(template.encode()).hexdigest()


class Catalog(PreviousCatalog):
    def __init__(self, path, *, compact_new=True):
        path = Path(path)
        assert_supported(path)
        existed = path.exists()
        super().__init__(path)
        self.db.create_function('next_template', 1, lambda s: pack(s)[0], deterministic=True)
        self.db.create_function('next_slots', 1, lambda s: pack(s)[1], deterministic=True)
        self.db.create_function('next_template_sha', 1, lambda s: pack(s)[2], deterministic=True)
        if not existed and compact_new:
            self.enable_compact()

    def summary(self, ignore_cycle=None):
        capture_table = 'capture_record' if self.compact else 'db_capture'
        return dict(versions=self.db.execute('SELECT count(*) FROM version').fetchone()[0],
            active_messages=self.db.execute('SELECT count(*) FROM head WHERE active=1').fetchone()[0],
            captures=self.db.execute(f'SELECT count(*) FROM {capture_table}').fetchone()[0],
            assets=self.db.execute('SELECT count(*) FROM asset').fetchone()[0],
            running_or_interrupted_cycles=self.db.execute("SELECT count(*) FROM cycle WHERE status IN ('running','interrupted') AND (? IS NULL OR id!=?)", (ignore_cycle,ignore_cycle)).fetchone()[0])

    def finish_cycle(self, ident, report):
        from .reports import encode_report
        from wechat_capture_v2.common import utcnow
        text = canonical(report)
        stored = encode_report(self.db, text) if self.compact else text
        with self.db:
            self.db.execute('UPDATE cycle SET finished=?,status=?,report_json=? WHERE id=?',
                            (utcnow(), report['status'], stored, ident))

    def report(self, ident):
        from .reports import decode_report
        row = self.db.execute('SELECT report_json FROM cycle WHERE id=?', (ident,)).fetchone()
        if row is None:
            raise KeyError(ident)
        return decode_report(self.db, row[0]) if row[0] is not None else None

    @property
    def compact(self):
        row = self.db.execute("SELECT value FROM meta WHERE key='next_evidence_storage'").fetchone()
        if row and row[0] != FORMAT:
            raise ValueError('unsupported evidence storage format')
        return row is not None

    def enable_compact(self, *, fault=None):
        """Explicit atomic extension; caller holds the next state's writer lock.

        Does not VACUUM or remove historical report files. For real archives,
        make an independently verified SQLite backup before invoking this.
        """
        if self.compact:
            return False
        if self.db.in_transaction:
            raise ValueError('migration needs a transaction boundary')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('''CREATE TABLE evidence_template(
                id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE, text TEXT NOT NULL)''')
            self.db.execute('ALTER TABLE db_capture RENAME TO capture_record')
            self.db.execute('ALTER TABLE capture_record RENAME COLUMN evidence_json TO slots_json')
            self.db.execute('ALTER TABLE capture_record ADD COLUMN template_id INTEGER REFERENCES evidence_template(id)')
            for rowid, text in self.db.execute('SELECT rowid,slots_json FROM capture_record'):
                template, slots, sha = pack(text)
                self.db.execute('INSERT OR IGNORE INTO evidence_template(sha256,text) VALUES(?,?)', (sha, template))
                item = self.db.execute('SELECT id,text FROM evidence_template WHERE sha256=?', (sha,)).fetchone()
                if item[1] != template:
                    raise ValueError('template SHA collision')
                self.db.execute('UPDATE capture_record SET slots_json=?,template_id=? WHERE rowid=?', (slots, item[0], rowid))
            self.db.execute('CREATE INDEX capture_template ON capture_record(template_id)')
            self.db.execute('''CREATE VIEW db_capture AS SELECT c.id,c.cycle_id,c.source_id,c.relative_path,c.signature,
                replace(replace(t.text,char(30)||'time'||char(30),coalesce(json_extract(c.slots_json,'$.t'),'')),
                char(30)||'reuse'||char(30),coalesce(json_extract(c.slots_json,'$.r'),'')) AS evidence_json,
                c.message_count,c.accepted FROM capture_record c LEFT JOIN evidence_template t ON t.id=c.template_id''')
            # Write-only functions are registered on the owned writer connection.
            # SELECT/readonly ATTACH never require Python functions/extensions.
            intern = '''INSERT OR IGNORE INTO evidence_template(sha256,text)
                VALUES(next_template_sha(NEW.evidence_json),next_template(NEW.evidence_json));
                SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM evidence_template
                    WHERE sha256=next_template_sha(NEW.evidence_json) AND text=next_template(NEW.evidence_json))
                    THEN RAISE(ABORT,'template collision') END;'''
            self.db.execute('''CREATE TRIGGER capture_insert INSTEAD OF INSERT ON db_capture BEGIN '''+intern+'''
                INSERT INTO capture_record(id,cycle_id,source_id,relative_path,signature,slots_json,message_count,accepted,template_id)
                SELECT NEW.id,NEW.cycle_id,NEW.source_id,NEW.relative_path,NEW.signature,next_slots(NEW.evidence_json),
                    NEW.message_count,NEW.accepted,id FROM evidence_template WHERE sha256=next_template_sha(NEW.evidence_json);
                END''')
            self.db.execute('''CREATE TRIGGER capture_update INSTEAD OF UPDATE ON db_capture BEGIN '''+intern+'''
                UPDATE capture_record SET id=NEW.id,cycle_id=NEW.cycle_id,source_id=NEW.source_id,
                    relative_path=NEW.relative_path,signature=NEW.signature,slots_json=next_slots(NEW.evidence_json),
                    message_count=NEW.message_count,accepted=NEW.accepted,
                    template_id=(SELECT id FROM evidence_template WHERE sha256=next_template_sha(NEW.evidence_json))
                    WHERE id=OLD.id;
                DELETE FROM evidence_template WHERE sha256=next_template_sha(OLD.evidence_json)
                    AND NOT EXISTS(SELECT 1 FROM capture_record WHERE template_id=evidence_template.id);
                END''')
            self.db.execute('''CREATE TRIGGER template_no_update BEFORE UPDATE ON evidence_template
                BEGIN SELECT RAISE(ABORT,'evidence templates are immutable'); END''')
            self.db.execute('''CREATE TRIGGER accepted_capture_no_update BEFORE UPDATE ON capture_record
                WHEN (SELECT finished FROM cycle WHERE id=OLD.cycle_id) IS NOT NULL
                BEGIN SELECT RAISE(ABORT,'finalized capture evidence is immutable'); END''')
            self.db.execute('''CREATE TRIGGER capture_no_delete BEFORE DELETE ON capture_record
                BEGIN SELECT RAISE(ABORT,'capture history is retained'); END''')
            self.db.execute("INSERT INTO meta VALUES('next_evidence_storage',?)", (FORMAT,))
            if fault:
                fault('before_commit')
            self.verify_templates()
            if list(self.db.execute('PRAGMA foreign_key_check')):
                raise ValueError('catalog FK migration failed')
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return True

    def verify_templates(self):
        if not self.compact:
            return dict(compact=False)
        for sha, text in self.db.execute('SELECT sha256,text FROM evidence_template'):
            if hashlib.sha256(text.encode()).hexdigest() != sha:
                raise ValueError('evidence template content mismatch')
        if self.db.execute('''SELECT 1 FROM capture_record c LEFT JOIN evidence_template t ON t.id=c.template_id
            WHERE t.id IS NULL OR NOT json_valid(c.slots_json) LIMIT 1''').fetchone():
            raise ValueError('missing template or invalid slots')
        if self.db.execute('SELECT 1 FROM db_capture WHERE evidence_json IS NULL OR NOT json_valid(evidence_json) LIMIT 1').fetchone():
            raise ValueError('invalid expanded evidence')
        return dict(compact=True, templates=self.db.execute('SELECT count(*) FROM evidence_template').fetchone()[0])

    def verify_reports(self):
        from .reports import decode_report
        count = 0
        for text, in self.db.execute('SELECT report_json FROM cycle WHERE report_json IS NOT NULL'):
            decode_report(self.db, text)
            count += 1
        return count
