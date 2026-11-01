"""Transaction-neutral, exact-byte content interning for next-only stores.

Read codecs are pure functions: attached databases never resolve IDs through a
callback's captured connection. JSON evidence is never canonicalized: optional
canonical-string recipes expand byte-exactly; other literals stay opaque.
"""
import hashlib
import json
import re
import zlib


def unpack(codec, data, byte_length):
    data = bytes(data)
    if not isinstance(byte_length, int) or byte_length < 0:
        raise ValueError('invalid content length')
    if codec == 'raw':
        result = data
    elif codec == 'zlib-1':
        decoder = zlib.decompressobj()
        result = decoder.decompress(data, byte_length + 1)
        if len(result) > byte_length or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('invalid compressed content')
    else:
        raise ValueError('unsupported content codec')
    if len(result) != byte_length:
        raise ValueError('content length mismatch')
    return result


def register_codec(db):
    db.create_function('next_content_bytes', 3, unpack, deterministic=True)
    db.create_function('next_content_text', 3,
        lambda codec, data, size: unpack(codec, data, size).decode('utf-8'), deterministic=True)
    db.create_function('next_content_render', 4, render_text, deterministic=True)


def render_text(codec, data, size, atoms):
    if codec != 'json-recipe-1':
        return unpack(codec, data, size).decode('utf-8')
    # Recipe framing is separate from user JSON; no sentinel replacement.
    if not isinstance(size, int) or size < 0:
        raise ValueError('invalid recipe content length')
    decoder = zlib.decompressobj()
    encoded_recipe = decoder.decompress(bytes(data), size * 4 + 4097)
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or
            len(encoded_recipe) > size * 4 + 4096):
        raise ValueError('invalid compressed JSON recipe')
    recipe = json.loads(encoded_recipe)
    resolved = {}
    for slot, atom_codec, encoded, atom_size in json.loads(atoms or '[]'):
        if slot in resolved:
            raise ValueError('duplicate recipe slot')
        value = unpack(atom_codec, bytes.fromhex(encoded), atom_size).decode('utf-8')
        resolved[slot] = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if not isinstance(recipe, list):
        raise ValueError('invalid JSON recipe')
    parts = []
    used = set()
    for part in recipe:
        if isinstance(part, str):
            parts.append(part)
        elif type(part) is int and part in resolved:
            parts.append(resolved[part])
            used.add(part)
        else:
            raise ValueError('missing or invalid recipe slot')
    if used != set(resolved):
        raise ValueError('unused recipe slot')
    result = ''.join(parts)
    if len(result.encode('utf-8')) != size:
        raise ValueError('recipe content length mismatch')
    return result


def sql_text_expression(alias, table='content_payload'):
    if not all(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) for name in (alias, table)):
        raise ValueError('invalid SQL alias')
    return f'''next_content_render({alias}.codec,{alias}.data,{alias}.byte_length,
        CASE WHEN {alias}.codec='json-recipe-1' THEN (SELECT json_group_array(
            json_array(r.slot,a.codec,hex(a.data),a.byte_length))
            FROM {table}_reference r JOIN {table} a ON a.id=r.atom_id
            WHERE r.payload_id={alias}.id) ELSE NULL END)'''


class ContentPool:
    def __init__(self, db, *, table='content_payload', create=False):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', table):
            raise ValueError('invalid content table')
        self.db, self.table = db, table
        register_codec(db)
        if create:
            db.execute(f'''CREATE TABLE {table}(
                id INTEGER PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN ('text','bytes')),
                sha256 TEXT NOT NULL,byte_length INTEGER NOT NULL CHECK(byte_length>=0),
                codec TEXT NOT NULL CHECK(codec IN ('raw','zlib-1','json-recipe-1')),data BLOB NOT NULL,
                UNIQUE(kind,sha256))''')
            db.execute(f'''CREATE TABLE {table}_reference(
                payload_id INTEGER NOT NULL REFERENCES {table}(id),slot INTEGER NOT NULL,
                atom_id INTEGER NOT NULL REFERENCES {table}(id),PRIMARY KEY(payload_id,slot))''')
            for operation in ('UPDATE', 'DELETE'):
                db.execute(f'''CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table}
                    BEGIN SELECT RAISE(ABORT,'content payloads are immutable'); END''')
                db.execute(f'''CREATE TRIGGER {table}_reference_no_{operation.lower()}
                    BEFORE {operation} ON {table}_reference
                    BEGIN SELECT RAISE(ABORT,'content references are immutable'); END''')

    def _intern(self, value, kind):
        sha = hashlib.sha256(value).hexdigest()
        previous = self.db.execute(
            f'SELECT id,codec,data,byte_length FROM {self.table} WHERE kind=? AND sha256=?',
            (kind, sha)).fetchone()
        if previous:
            if self._read(previous[0], previous[1], previous[2], previous[3]) != value:
                raise ValueError('content digest collision')
            return previous[0]
        compressed = zlib.compress(value, level=6)
        codec, data = ('zlib-1', compressed) if len(compressed) < len(value) else ('raw', value)
        return self.db.execute(f'''INSERT INTO {self.table}(kind,sha256,byte_length,codec,data)
            VALUES(?,?,?,?,?)''', (kind, sha, len(value), codec, data)).lastrowid

    def intern_text(self, text):
        if not isinstance(text, str):
            raise TypeError('content text must be str')
        return self._intern(text.encode('utf-8'), 'text')

    def intern_json(self, text):
        """Share canonical large string leaves; preserve other JSON literally.

        Noncanonical JSON (including duplicate keys and unusual numeric lexemes)
        remains opaque exact text. Atoms share the same IDs as body text.
        """
        if not isinstance(text, str):
            raise TypeError('JSON content must be text')
        value = text.encode('utf-8')
        sha = hashlib.sha256(value).hexdigest()
        previous = self.db.execute(f'''SELECT id,codec,data,byte_length FROM {self.table}
            WHERE kind=? AND sha256=?''', ('text', sha)).fetchone()
        if previous:
            if self._read(*previous) != value:
                raise ValueError('content digest collision')
            return previous[0]
        parsed = json.loads(text)
        try:
            canonical = json.dumps(parsed, ensure_ascii=False, sort_keys=True,
                                   separators=(',', ':'), allow_nan=False)
        except (ValueError, OverflowError):
            # A valid lexical JSON number may exceed Python float range.
            # Its source text, not the parsed float, is the stored evidence.
            return self.intern_text(text)
        if canonical != text:
            return self.intern_text(text)
        recipe, atoms, position = [], [], 0
        for match in re.finditer(r'"(?:[^"\\]|\\.)*"', text):
            leaf = json.loads(match.group())
            if len(leaf.encode('utf-8')) < 256:
                continue
            atom = self.intern_text(leaf)
            # A body may itself equal an already-interned JSON document. Keep
            # that leaf literal rather than constructing recursive recipes.
            if self.db.execute(f'SELECT codec FROM {self.table} WHERE id=?', (atom,)).fetchone()[0] == 'json-recipe-1':
                continue
            recipe.extend((text[position:match.start()], len(atoms)))
            atoms.append(atom)
            position = match.end()
        if not atoms:
            return self.intern_text(text)
        recipe.append(text[position:])
        data = zlib.compress(json.dumps(recipe, ensure_ascii=False,
            separators=(',', ':')).encode('utf-8'), level=6)
        identity = self.db.execute(f'''INSERT INTO {self.table}(kind,sha256,byte_length,codec,data)
            VALUES('text',?,?,'json-recipe-1',?)''', (sha, len(value), data)).lastrowid
        self.db.executemany(f'INSERT INTO {self.table}_reference VALUES(?,?,?)',
                            ((identity, slot, atom) for slot, atom in enumerate(atoms)))
        if self.get_text(identity) != text:
            raise ValueError('JSON recipe was not byte exact')
        return identity

    def _read(self, identity, codec, data, size):
        if codec != 'json-recipe-1':
            return unpack(codec, data, size)
        atoms = list(map(list, self.db.execute(f'''SELECT r.slot,a.codec,hex(a.data),a.byte_length
            FROM {self.table}_reference r JOIN {self.table} a ON a.id=r.atom_id
            WHERE r.payload_id=? ORDER BY r.slot''', (identity,))))
        return render_text(codec, data, size, json.dumps(atoms)).encode('utf-8')

    def intern_bytes(self, value):
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError('content bytes must be bytes-like')
        return self._intern(bytes(value), 'bytes')

    def _get(self, identity, kind):
        row = self.db.execute(f'SELECT kind,codec,data,byte_length FROM {self.table} WHERE id=?',
                              (identity,)).fetchone()
        if row is None:
            raise KeyError(identity)
        if row[0] != kind:
            raise TypeError('content kind mismatch')
        return self._read(identity, row[1], row[2], row[3])

    def get_text(self, identity):
        return self._get(identity, 'text').decode('utf-8')

    def get_bytes(self, identity):
        return self._get(identity, 'bytes')

    def verify(self):
        count = total = 0
        for identity, kind, sha, codec, data, size in self.db.execute(
                f'SELECT id,kind,sha256,codec,data,byte_length FROM {self.table}'):
            value = self._read(identity, codec, data, size)
            if hashlib.sha256(value).hexdigest() != sha:
                raise ValueError('content digest mismatch')
            if kind == 'text':
                value.decode('utf-8')
            elif kind != 'bytes':
                raise ValueError('unsupported content kind')
            count += 1
            total += size
        return dict(payloads_verified=count, uncompressed_bytes=total)
