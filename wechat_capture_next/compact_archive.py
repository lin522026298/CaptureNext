"""Next-only compact archive. Legacy WUA files are inputs, never migrated.

Compatibility views expose exact original observation columns on codec-enabled
connections. Old WUA tools deliberately reject this independent format.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from wua.store import (ArchiveStore, RULE_VERSION, SCHEMA_VERSION as WUA_SCHEMA,
                       _DERIVED_TABLES, _identifier, _json)
from .merge import LeanArchiveStore
from .content_pool import ContentPool, register_codec, sql_text_expression

SCHEMA_VERSION = 'next-compact-archive-1'
# Connection-local, on-demand page-cache budget for heavy owned writers.
# This is not preallocated, not persisted, and not a message/acquisition limit.
HEAVY_CACHE_KIB = 128 * 1024
OBSERVATION_COLUMNS = ('observation_id', 'snapshot_id', 'db_relative_path', 'table_name',
    'native_locator_json', 'row_hash', 'raw_record_json', 'normalized_json',
    'account_alias', 'conversation_id', 'sender_id', 'direction', 'event_time',
    'raw_time_json', 'time_unit', 'message_type', 'server_id', 'body_text')
JSON_COLUMNS = ('native_locator_json', 'raw_record_json', 'normalized_json', 'raw_time_json')
LOGICAL_COLUMNS = ('logical_id', 'representative_observation_id', 'account_alias',
    'conversation_id', 'sender_id', 'direction', 'event_time', 'message_type',
    'server_id', 'body_text', 'observation_count', 'source_count', 'snapshot_count',
    'conflict_count', 'rule_version')
LOGICAL_STORED = (0, 1, 10, 11, 12, 13, 14)


def connect_archive(path, *, readonly=False, create=False,immutable=False):
    """One URI-aware connection; callers may attach read-only inputs to it."""
    if immutable and not readonly:raise ValueError('immutable is for guarded cold readers only')
    if str(path) == ':memory:':
        if readonly:
            raise ValueError('an in-memory archive cannot be opened readonly')
        db = sqlite3.connect(':memory:', uri=True, isolation_level=None)
    else:
        mode = 'ro' if readonly else 'rwc' if create else 'rw'
        db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=' + mode+('&immutable=1' if immutable else ''),
                             uri=True, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA temp_store=MEMORY')
    if not readonly:
        db.execute(f'PRAGMA cache_size=-{HEAVY_CACHE_KIB}')
    register_codec(db)
    if readonly:
        db.execute('PRAGMA query_only=ON')
    return db


class CompactArchive(LeanArchiveStore):
    """Reuse frozen merge/read semantics, not the legacy constructor or schema.

    Opening never migrates an archive. ``create=True`` permits initialization of
    an empty target only; it does not adopt or rewrite an old WUA database.
    """
    def __init__(self, path, *, readonly=False, create=False, fts=True,immutable=False):
        self.path, self.readonly = str(path), readonly
        self._db = connect_archive(path, readonly=readonly, create=create,immutable=immutable)
        self.last_rebuild_writes = {}
        self.last_rebuild_reads = {}
        self.new_observation_ids = []
        try:
            objects = dict(self._db.execute('SELECT name,type FROM sqlite_master'))
            if not objects:
                if readonly or not (create or str(path) == ':memory:'):
                    raise ValueError('compact archive does not exist')
                self._create_schema(fts)
            version = dict(self._db.execute('SELECT key,value FROM archive_meta'))
            if version.get('schema_version') != SCHEMA_VERSION or version.get('rule_version') != RULE_VERSION:
                raise ValueError('unsupported compact archive schema or rule version')
            required = {'message_observation': 'view', 'logical_message': 'view',
                'observation_record': 'table', 'logical_record': 'table',
                'content_payload': 'table', 'content_payload_reference': 'table',
                'body_record': 'table', 'body_content': 'view', 'next_merge_projection': 'table',
                'next_import_meta': 'table'}
            actual = dict(self._db.execute('SELECT name,type FROM sqlite_master'))
            if any(actual.get(name) != kind for name, kind in required.items()):
                raise ValueError('incomplete compact archive schema')
            self.pool = ContentPool(self._db)
            fts_row = self._db.execute("SELECT sql FROM sqlite_master WHERE name='message_fts'").fetchone()
            self.fts_enabled = fts_row is not None
            self.fts_tokenizer = ('trigram' if fts_row and 'trigram' in fts_row[0]
                                  else 'unicode61' if fts_row else None)
        except BaseException:
            if self._db.in_transaction:
                self._db.execute('ROLLBACK')
            self._db.close()
            raise

    def _create_schema(self, enable_fts):
        db = self._db
        db.execute('BEGIN IMMEDIATE')
        try:
            self.pool = ContentPool(db, create=True)
            for statement in (
                'CREATE TABLE archive_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)',
                'CREATE TABLE source_device(source_id TEXT PRIMARY KEY,metadata_json TEXT NOT NULL)',
                '''CREATE TABLE source_snapshot(snapshot_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES source_device(source_id),metadata_json TEXT NOT NULL)''',
                'CREATE TABLE body_record(id INTEGER PRIMARY KEY REFERENCES content_payload(id))',
                '''CREATE TABLE observation_record(
                    observation_id TEXT PRIMARY KEY,snapshot_id TEXT NOT NULL REFERENCES source_snapshot(snapshot_id),
                    db_relative_path TEXT NOT NULL,table_name TEXT NOT NULL,
                    native_locator_json INTEGER NOT NULL REFERENCES content_payload(id),row_hash TEXT NOT NULL,
                    raw_record_json INTEGER NOT NULL REFERENCES content_payload(id),
                    normalized_json INTEGER NOT NULL REFERENCES content_payload(id),
                    account_alias TEXT,conversation_id TEXT,sender_id TEXT,direction TEXT,event_time TEXT,
                    raw_time_json INTEGER NOT NULL REFERENCES content_payload(id),time_unit TEXT,
                    message_type TEXT,server_id TEXT,body_text INTEGER REFERENCES body_record(id),
                    UNIQUE(snapshot_id,db_relative_path,table_name,native_locator_json,row_hash))''',
                'CREATE INDEX observation_snapshot ON observation_record(snapshot_id)',
                'CREATE INDEX observation_body ON observation_record(body_text,observation_id)',
                '''CREATE INDEX observation_locator ON observation_record(
                    snapshot_id,db_relative_path,table_name,native_locator_json)''',
                '''CREATE TABLE logical_record(logical_id TEXT PRIMARY KEY,
                    representative_observation_id TEXT NOT NULL REFERENCES observation_record(observation_id),
                    observation_count INTEGER NOT NULL,source_count INTEGER NOT NULL,
                    snapshot_count INTEGER NOT NULL,conflict_count INTEGER NOT NULL,rule_version TEXT NOT NULL)''',
                '''CREATE TABLE message_link(observation_id TEXT PRIMARY KEY REFERENCES observation_record(observation_id),
                    logical_id TEXT NOT NULL REFERENCES logical_record(logical_id),rule_version TEXT NOT NULL,
                    rule_name TEXT NOT NULL,confidence TEXT NOT NULL,evidence_json TEXT NOT NULL)''',
                'CREATE INDEX link_logical ON message_link(logical_id)',
                'CREATE VIEW dedupe_decision AS SELECT * FROM message_link',
                '''CREATE TABLE conflict(logical_id TEXT NOT NULL REFERENCES logical_record(logical_id),
                    field TEXT NOT NULL,values_json TEXT NOT NULL,rule_version TEXT NOT NULL,
                    PRIMARY KEY(logical_id,field))''',
                '''CREATE TABLE dedupe_candidate(candidate_id TEXT PRIMARY KEY,
                    left_logical_id TEXT NOT NULL REFERENCES logical_record(logical_id),
                    right_logical_id TEXT NOT NULL REFERENCES logical_record(logical_id),
                    confidence TEXT NOT NULL,rule_name TEXT NOT NULL,evidence_json TEXT NOT NULL,
                    rule_version TEXT NOT NULL,CHECK(left_logical_id<right_logical_id))''',
                '''CREATE TABLE next_import_origin(origin_id TEXT PRIMARY KEY,metadata_json TEXT NOT NULL)''',
                '''CREATE TABLE next_import_meta(origin_id TEXT NOT NULL REFERENCES next_import_origin(origin_id),
                    key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(origin_id,key))''',
                '''CREATE TABLE next_import_member(origin_id TEXT NOT NULL REFERENCES next_import_origin(origin_id),
                    original_observation_id TEXT NOT NULL,observation_id TEXT NOT NULL REFERENCES observation_record(observation_id),
                    PRIMARY KEY(origin_id,original_observation_id))'''):
                db.execute(statement)
            projected, joins = [], []
            for name in OBSERVATION_COLUMNS:
                if name in JSON_COLUMNS or name == 'body_text':
                    alias = 'p_' + name
                    joins.append(f'LEFT JOIN content_payload {alias} ON {alias}.id=o.{name}')
                    expression = sql_text_expression(alias)
                    projected.append(f'CASE WHEN o.{name} IS NULL THEN NULL ELSE {expression} END AS {name}')
                else:
                    projected.append('o.' + name)
            db.execute('CREATE VIEW message_observation AS SELECT ' + ','.join(projected) +
                       ' FROM observation_record o ' + ' '.join(joins))
            fields = ['l.' + name if i in LOGICAL_STORED else 'o.' + name
                      for i, name in enumerate(LOGICAL_COLUMNS)]
            db.execute('CREATE VIEW logical_message AS SELECT ' + ','.join(fields) +
                ' FROM logical_record l JOIN message_observation o ON o.observation_id=l.representative_observation_id')
            db.execute('CREATE VIEW body_content AS SELECT p.id,' + sql_text_expression('p') +
                       ' AS body_text FROM body_record b JOIN content_payload p ON p.id=b.id')
            for table in ('source_device', 'source_snapshot', 'observation_record', 'body_record',
                          'next_import_origin', 'next_import_member', 'next_import_meta'):
                for operation in ('UPDATE', 'DELETE'):
                    db.execute(f'''CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table}
                        BEGIN SELECT RAISE(ABORT,'archive provenance is immutable'); END''')
            db.executemany('INSERT INTO archive_meta VALUES(?,?)',
                           [('schema_version', SCHEMA_VERSION), ('rule_version', RULE_VERSION)])
            if enable_fts:
                for tokenizer in ('trigram', 'unicode61'):
                    try:
                        db.execute("CREATE VIRTUAL TABLE message_fts USING fts5(body_text,"
                            f"content='body_content',content_rowid='id',tokenize='{tokenizer}')")
                        break
                    except sqlite3.OperationalError as error:
                        if 'no such module' in str(error).lower():
                            break
                        if 'tokenizer' not in str(error).lower():
                            raise
            from .compact_delta import ensure_delta_schema
            ensure_delta_schema(self)
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK')
            raise

    @contextmanager
    def transaction(self):
        self._writable()
        if self._db.in_transaction:
            raise ValueError('archive transaction already active')
        before = len(self.new_observation_ids)
        self._db.execute('BEGIN IMMEDIATE')
        try:
            yield self
            self._db.execute('COMMIT')
            del self.new_observation_ids[before:]
        except BaseException:
            self._db.execute('ROLLBACK')
            del self.new_observation_ids[before:]
            raise

    def insert_source_exact(self, source_id, metadata_json):
        return self._insert_metadata('source_device', source_id, metadata_json)

    def insert_snapshot_exact(self, snapshot_id, source_id, metadata_json):
        return self._insert_metadata('source_snapshot', snapshot_id, metadata_json, source_id)

    def _insert_metadata(self, table, identity, metadata, source_id=None):
        self._writable()
        json.loads(metadata)
        values = (identity, metadata) if table == 'source_device' else (identity, source_id, metadata)
        key = 'source_id' if table == 'source_device' else 'snapshot_id'
        previous = self._db.execute(f'SELECT * FROM {table} WHERE {key}=?', (identity,)).fetchone()
        if previous:
            if tuple(previous) != values:
                raise ValueError('immutable source/snapshot metadata mismatch')
            return False
        self._db.execute(f'INSERT INTO {table} VALUES(' + ','.join('?' for _ in values) + ')', values)
        return True

    prepared_observation = staticmethod(ArchiveStore._prepare_row)

    def insert_prepared(self, prepared, *, origin=None):
        """Insert an exact prepared WUA projection; return False on exact replay."""
        self._writable()
        if not self._db.in_transaction:
            raise ValueError('prepared observations require an archive transaction')
        if set(prepared) != set(OBSERVATION_COLUMNS):
            raise ValueError('complete prepared observation columns required')
        raw = prepared['raw_record_json']
        if hashlib.sha256(raw.encode('utf-8')).hexdigest() != prepared['row_hash']:
            raise ValueError('raw observation hash mismatch')
        for name in JSON_COLUMNS:
            json.loads(prepared[name])
        previous = self._db.execute('SELECT * FROM message_observation WHERE observation_id=?',
                                    (prepared['observation_id'],)).fetchone()
        if previous:
            if dict(previous) != dict(prepared):
                raise ValueError('existing observation has a different exact interpretation')
            added = False
        else:
            physical = dict(prepared)
            for name in JSON_COLUMNS:
                physical[name] = self.pool.intern_json(prepared[name])
            body = prepared['body_text']
            if body is not None:
                body_id = self.pool.intern_text(body)
                if not self._db.execute('SELECT 1 FROM body_record WHERE id=?', (body_id,)).fetchone():
                    self._db.execute('INSERT INTO body_record VALUES(?)', (body_id,))
                    if self.fts_enabled:
                        self._db.execute('INSERT INTO message_fts(rowid,body_text) VALUES(?,?)', (body_id, body))
                physical['body_text'] = body_id
            self._db.execute('INSERT INTO observation_record VALUES(' + ','.join('?' for _ in OBSERVATION_COLUMNS) + ')',
                             tuple(physical[name] for name in OBSERVATION_COLUMNS))
            from .compact_delta import register_observation
            register_observation(self, dict(prepared))
            self.new_observation_ids.append(prepared['observation_id'])
            added = True
        if origin is not None:
            self._db.execute('INSERT OR IGNORE INTO next_import_member VALUES(?,?,?)',
                             (origin, prepared['observation_id'], prepared['observation_id']))
        return added

    def import_observations(self, source_meta, snapshot_meta, rows):
        source_id, snapshot_id = _identifier(source_meta, 'source_id'), _identifier(snapshot_meta, 'snapshot_id')
        if snapshot_meta.get('source_id', source_id) != source_id:
            raise ValueError('snapshot source_id does not match source_meta')
        counts = dict(input_rows=0, added_observations=0, replayed_observations=0,
                      revised_observations=0, added_sources=0, added_snapshots=0)
        with self.transaction():
            counts['added_sources'] = int(self.insert_source_exact(source_id, _json(source_meta)))
            counts['added_snapshots'] = int(self.insert_snapshot_exact(snapshot_id, source_id, _json(snapshot_meta)))
            for row in rows:
                counts['input_rows'] += 1
                prepared = self.prepared_observation(snapshot_id, row)
                existing = self._db.execute('SELECT 1 FROM observation_record WHERE observation_id=?',
                                            (prepared['observation_id'],)).fetchone()
                revised = None
                if not existing:
                    locator_id = self.pool.intern_json(prepared['native_locator_json'])
                    revised = self._db.execute('''SELECT 1 FROM observation_record WHERE snapshot_id=?
                        AND db_relative_path=? AND table_name=? AND native_locator_json=? LIMIT 1''',
                        (snapshot_id, prepared['db_relative_path'], prepared['table_name'], locator_id)).fetchone()
                if self.insert_prepared(prepared):
                    counts['added_observations'] += 1
                    counts['revised_observations'] += int(revised is not None)
                else:
                    counts['replayed_observations'] += 1
            counts.update(self._rebuild())
        counts['idempotent_replay'] = not any(counts[key] for key in
            ('added_observations', 'added_sources', 'added_snapshots')) and not counts['rebuild_changed']
        return counts

    def import_legacy_rows(self, source, origin=None):
        """Copy exact source rows from a caller-owned read-only SQLite connection.

        Own a transaction only when the caller has not already opened one.
        Source metadata and JSON literals are copied verbatim, not normalized.
        """
        self._writable()
        metadata = dict(source.execute('SELECT key,value FROM archive_meta'))
        if metadata.get('schema_version') not in (WUA_SCHEMA, SCHEMA_VERSION) or metadata.get('rule_version') != RULE_VERSION:
            raise ValueError('unsupported input archive format')
        for table, expected in (('message_observation', OBSERVATION_COLUMNS),
                ('source_device', ('source_id', 'metadata_json')),
                ('source_snapshot', ('snapshot_id', 'source_id', 'metadata_json'))):
            actual = tuple(row[1] for row in source.execute(f'PRAGMA table_info({table})'))
            if actual != expected:
                raise ValueError('unsupported input columns; refusing to discard unknown archive fields')
        if self._db.in_transaction:
            return self._import_legacy_rows(source, origin)
        with self.transaction():
            result = self._import_legacy_rows(source, origin)
            result.update(self._rebuild())
            return result

    def _import_legacy_rows(self, source, origin):
        if origin is None:
            # An import receipt identity, not an inferred physical device ID.
            identity_material = [list(map(list, source.execute(f'SELECT * FROM {table} ORDER BY 1,2')))
                for table in ('archive_meta', 'source_device', 'source_snapshot')]
            origin = {'origin_id': 'metadata_' + hashlib.sha256(_json(identity_material).encode()).hexdigest(),
                      'kind': 'archive-metadata-receipt'}
        if origin is not None:
            origin_id = origin if isinstance(origin, str) else _identifier(origin, 'origin_id')
            literal = _json({'origin_id': origin}) if isinstance(origin, str) else _json(origin)
            previous = self._db.execute('SELECT metadata_json FROM next_import_origin WHERE origin_id=?', (origin_id,)).fetchone()
            if previous and previous[0] != literal:
                raise ValueError('immutable import origin mismatch')
            if not previous:
                self._db.execute('INSERT INTO next_import_origin VALUES(?,?)', (origin_id, literal))
        else:
            origin_id = None
        for key, value in source.execute('SELECT key,value FROM archive_meta ORDER BY key'):
            old = self._db.execute('SELECT value FROM next_import_meta WHERE origin_id=? AND key=?',
                                   (origin_id, key)).fetchone()
            if old and old[0] != value:
                raise ValueError('immutable imported archive metadata mismatch')
            if not old:
                self._db.execute('INSERT INTO next_import_meta VALUES(?,?,?)', (origin_id, key, value))
        counts = dict(input_rows=0, added_observations=0, replayed_observations=0)
        for identity, literal in source.execute('SELECT source_id,metadata_json FROM source_device ORDER BY source_id'):
            self.insert_source_exact(identity, literal)
        for identity, source_id, literal in source.execute('SELECT snapshot_id,source_id,metadata_json FROM source_snapshot ORDER BY snapshot_id'):
            self.insert_snapshot_exact(identity, source_id, literal)
        cursor = source.execute('SELECT ' + ','.join(OBSERVATION_COLUMNS) + ' FROM message_observation ORDER BY observation_id')
        for row in cursor:
            counts['input_rows'] += 1
            added = self.insert_prepared(dict(zip(OBSERVATION_COLUMNS, row)), origin=origin_id)
            counts['added_observations' if added else 'replayed_observations'] += 1
        return counts

    def _apply_rows(self, table, delta, *, delete=False):
        if table != 'logical_message':
            return super()._apply_rows(table, delta, delete=delete)
        if delete:
            self._db.executemany('DELETE FROM logical_record WHERE logical_id=?', delta['delete'])
            return
        self._db.executemany('INSERT INTO logical_record VALUES(?,?,?,?,?,?,?)',
            (tuple(row[i] for i in LOGICAL_STORED) for row in delta['insert']))
        self._db.executemany('''UPDATE logical_record SET representative_observation_id=?,observation_count=?,
            source_count=?,snapshot_count=?,conflict_count=?,rule_version=? WHERE logical_id=?''',
            (tuple(row[i] for i in LOGICAL_STORED[1:]) + (row[0],) for row in delta['update']))

    def _rebuild(self):
        desired = self._desired_state()
        deltas = {name: self._delta(name, desired[name], 2 if name == 'conflict' else 1) for name in _DERIVED_TABLES}
        changed = any(any(delta.values()) for delta in deltas.values())
        if changed:
            self._apply_rows('logical_message', deltas['logical_message'])
            for name in ('dedupe_candidate', 'conflict', 'message_link'):
                self._apply_rows(name, deltas[name], delete=True)
            for name in ('message_link', 'conflict', 'dedupe_candidate'):
                self._apply_rows(name, deltas[name])
            self._apply_rows('logical_message', deltas['logical_message'], delete=True)
        self.last_rebuild_writes = {name: {action: len(rows) for action, rows in delta.items()}
                                    for name, delta in deltas.items()}
        return dict(rebuild_changed=changed, added_logical_messages=len(deltas['logical_message']['insert']), totals=self.stats())

    def rebuild_logical(self, *, rule_version=RULE_VERSION):
        if rule_version != RULE_VERSION:
            raise ValueError('unsupported deduplication rule version')
        with self.transaction():
            from .compact_delta import register_observation
            self._db.execute('DELETE FROM next_merge_projection')
            for row in self._merge_rows():
                register_observation(self, row)
            result = self._rebuild()
            result['search_index_repaired'] = False
            if self.fts_enabled:
                try:
                    self._db.execute("INSERT INTO message_fts(message_fts,rank) VALUES('integrity-check',1)")
                except sqlite3.DatabaseError:
                    self._db.execute("INSERT INTO message_fts(message_fts) VALUES('rebuild')")
                    self._db.execute("INSERT INTO message_fts(message_fts,rank) VALUES('integrity-check',1)")
                    result['search_index_repaired'] = True
                    result['rebuild_changed'] = True
            return result

    def list_messages(self, **kwargs):
        # The frozen reader's literal verification remains the final authority.
        # Add unique-body FTS restriction before its pagination, not afterwards.
        search = kwargs.get('search')
        if (search and isinstance(search, str) and self.fts_tokenizer == 'trigram' and
            len(search) >= 3 and re.fullmatch(r'[A-Za-z0-9\u4e00-\u9fff ]+', search)):
            return self._list_messages_fts(**kwargs)
        tokenizer = self.fts_tokenizer
        self.fts_tokenizer = None
        try:
            return ArchiveStore.list_messages(self, **kwargs)
        finally:
            self.fts_tokenizer = tokenizer

    def _list_messages_fts(self, **kwargs):
        # Reuse frozen validation/filtering with a TEMP-less connection proxy
        # that substitutes only the FTS restriction, before LIMIT/OFFSET.
        archive = self
        original = self._db
        class SearchConnection:
            def execute(self, query, parameters=()):
                if query.startswith('SELECT m.* FROM logical_message m'):
                    marker = 'm.logical_id IN (SELECT logical_id FROM message_fts WHERE message_fts MATCH ?)'
                    replacement = '''m.logical_id IN (SELECT DISTINCT l.logical_id FROM message_fts
                        JOIN observation_record bo ON bo.body_text=message_fts.rowid
                        JOIN message_link l ON l.observation_id=bo.observation_id WHERE message_fts MATCH ?)'''
                    query = query.replace(marker, replacement)
                return original.execute(query, parameters)
        try:
            archive._db = SearchConnection()
            return ArchiveStore.list_messages(archive, **kwargs)
        finally:
            archive._db = original

    def semantic_digest(self, *, projection='wua-observations-1'):
        if projection != WUA_SCHEMA:
            raise ValueError('unsupported semantic projection')
        digest = hashlib.sha256()
        for name in ('archive_meta', 'source_device', 'source_snapshot', 'message_observation', *_DERIVED_TABLES):
            digest.update((_json(name) + '\n').encode('utf-8'))
            rows = ([('rule_version', RULE_VERSION), ('schema_version', WUA_SCHEMA)] if name == 'archive_meta'
                    else self._db.execute(f'SELECT * FROM {name} ORDER BY 1,2'))
            for row in rows:
                digest.update((_json(list(row)) + '\n').encode('utf-8'))
        return digest.hexdigest()

    def stats(self):
        # Counts do not require JSON, body decoding, or compatibility-view joins.
        counts = {name: self._db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
            for name, table in (('sources', 'source_device'), ('snapshots', 'source_snapshot'),
                ('observations', 'observation_record'), ('logical_messages', 'logical_record'),
                ('conflicts', 'conflict'), ('candidates', 'dedupe_candidate'))}
        counts['automatic_duplicate_links'] = counts['observations'] - counts['logical_messages']
        counts['candidate_confidence'] = dict(self._db.execute('''SELECT confidence,COUNT(*)
            FROM dedupe_candidate GROUP BY confidence ORDER BY confidence'''))
        counts['rule_version'] = RULE_VERSION
        return counts

    def integrity_check(self):
        result = ArchiveStore.integrity_check(self)
        result['content'] = self.pool.verify()
        from .viewer_identity import verify as verify_identity
        result['identities']=verify_identity(self)
        # Every unique payload's decoded bytes were just authenticated. Bind
        # each raw observation to that verified text digest without decoding the
        # same raw document again for every source/snapshot observation.
        verified, invalid = self._db.execute('''SELECT count(*),coalesce(sum(CASE WHEN
            p.id IS NULL OR p.kind!='text' OR p.sha256!=o.row_hash THEN 1 ELSE 0 END),0)
            FROM observation_record o LEFT JOIN content_payload p ON p.id=o.raw_record_json''').fetchone()
        if invalid:
            raise ValueError('archive raw observation hash or payload binding mismatch')
        result['raw_observations_verified'] = verified
        result['fts_verified'] = self._check_fts()
        result['fts_status'] = ('verified' if result['fts_verified'] else
            'not_verified_readonly' if self.readonly and self.fts_enabled else 'disabled')
        return result

    def _check_fts(self):
        """Authenticate postings against external content without persisting writes.

        SQLite implements this verification as a special INSERT command, so a
        truly read-only viewer must explicitly report the check as unperformed.
        Only explicit rebuild_logical may repair a failed index.
        """
        if not self.fts_enabled or self.readonly:
            return False
        self._db.execute('SAVEPOINT compact_fts_integrity')
        try:
            self._db.execute("INSERT INTO message_fts(message_fts,rank) VALUES('integrity-check',1)")
        finally:
            self._db.execute('ROLLBACK TO compact_fts_integrity')
            self._db.execute('RELEASE compact_fts_integrity')
        return True

    def storage_stats(self):
        db = self._db
        return dict(unique_payloads=db.execute('SELECT count(*) FROM content_payload').fetchone()[0],
            stored_payload_bytes=db.execute('SELECT coalesce(sum(length(data)),0) FROM content_payload').fetchone()[0],
            uncompressed_payload_bytes=db.execute('SELECT coalesce(sum(byte_length),0) FROM content_payload').fetchone()[0],
            canonical_json_recipes=db.execute("SELECT count(*) FROM content_payload WHERE codec='json-recipe-1'").fetchone()[0],
            shared_string_references=db.execute('SELECT count(*) FROM content_payload_reference').fetchone()[0],
            unique_bodies=db.execute('SELECT count(*) FROM body_record').fetchone()[0],
            residual_duplication='Small JSON leaves, noncanonical JSON, and derived evidence are not leaf-factored.')
