"""Small, atomic product preferences, never chat data or credentials."""
import json
import os
from pathlib import Path

from .console import _file, _parents, _unique_object

DEFAULTS = dict(auto_capture=True, launch_at_login=False, notifications=True,
    backup_enabled=True, backup_hours=24, backup_include_secrets=False, verify_enabled=True, verify_hours=168,
    heavy_start=1, heavy_end=7, webui_on_start=False)
LEGACY_FIELDS = frozenset(DEFAULTS) - {'backup_include_secrets'}


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS):
        raise ValueError('complete known settings required')
    for key, default in DEFAULTS.items():
        if type(value[key]) is not type(default):
            raise ValueError('invalid setting type')
    if any(not 1 <= value[k] <= 8760 for k in ('backup_hours', 'verify_hours')):
        raise ValueError('schedule interval must be 1..8760 hours')
    if any(not 0 <= value[k] <= 23 for k in ('heavy_start', 'heavy_end')):
        raise ValueError('hour must be 0..23')
    return dict(value)


def load(path):
    path = Path(path)
    _parents(path.parent)
    if not os.path.lexists(path):
        return dict(DEFAULTS)
    _file(path)
    value=json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique_object)
    # Only the complete previous schema is compatible. Reading never rewrites
    # preferences or opts a user into sensitive key material automatically.
    if isinstance(value,dict) and set(value)==LEGACY_FIELDS:
        value=dict(value,backup_include_secrets=False)
    return validate(value)


def save(path, value):
    value = validate(value)
    return atomic_json(path,value)


def atomic_json(path,value):
    path = Path(path)
    _parents(path.parent)
    if os.path.lexists(path):
        _file(path)
        if json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=_unique_object) == value:
            return False
    temporary = path.with_name(path.name+'.pending')
    if os.path.lexists(temporary):
        _file(temporary)
        # A crash before replace leaves a complete or partial unpublished
        # preference, never an archive record. Recover only this exact owned
        # temporary path; do not adopt its possibly incomplete value.
        temporary.unlink()
    # Never overwrite a foreign/linked stale temporary file.
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return True


def in_window(hour, start, end):
    return start == end or (start <= hour < end if start < end else hour >= start or hour < end)
