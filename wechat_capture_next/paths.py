"""Lexical local path boundaries shared by the new delivery APIs.

This local-only format deliberately rejects UNC/device/extended namespace
aliases, rather than comparing equivalent Windows paths with different drives.
No resolve() before link checks; callers validate each existing ancestor.
"""
import os
from pathlib import Path, PureWindowsPath
import re


def local_absolute(value, *, allow_relative=False, lexical=False):
    text = os.fspath(value)
    if not isinstance(text, str) or any(ord(ch) < 32 for ch in text):
        raise ValueError('control characters are forbidden in local paths')
    normalized = text.replace('\\', '/')
    if (normalized.startswith('//') or normalized.startswith('/??/')
            or normalized.lower().startswith('/device/')):
        raise ValueError('UNC, extended and device path aliases are outside local scope')
    drive = PureWindowsPath(text).drive
    if drive and not re.fullmatch('[A-Za-z]:', drive):
        raise ValueError('non-DOS local path namespace')
    path = Path(text)
    if '..' in path.parts or (not allow_relative and not path.is_absolute()):
        raise ValueError('an absolute path without traversal is required')
    path = Path(os.path.abspath(path))
    if os.name == 'nt':
        for part in path.parts[1:]:
            if (part.endswith((' ','.')) or PureWindowsPath(part).is_reserved()
                    or any(ch in '<>:"|?*' for ch in part)):
                raise ValueError('ambiguous Windows path component')
    if lexical:
        # Stored protection roots must already be canonical long paths. Do not
        # probe an offline source merely to restore a backup elsewhere.
        if os.name == 'nt' and any(re.fullmatch(r'[^~]{1,6}~[0-9]+(?:\..*)?', part) for part in path.parts):
            raise ValueError('stored source roots require canonical long paths')
        return path
    for part in reversed((path,*path.parents)):
        if os.path.lexists(part):
            info = part.lstat()
            if part.is_symlink() or getattr(info,'st_file_attributes',0) & 0x400:
                raise ValueError('links/reparse points are outside local path scope')
    # All existing ancestors were checked BEFORE resolving. Windows realpath
    # expands DOS 8.3 aliases, including when only the final child is absent.
    return path.resolve(strict=False)


def safe_name(value):
    if (not isinstance(value, str) or not value or value in ('.','..') or len(value) > 120
            or value != value.strip() or value.endswith('.') or '/' in value or '\\' in value
            or any(ord(ch) < 32 or ch in '<>:"|?*' for ch in value)
            or PureWindowsPath(value).is_reserved()):
        raise ValueError('a safe fresh local name is required')
    return value
