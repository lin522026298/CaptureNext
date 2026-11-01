"""Reject links before any next-state writer (including the lock file) opens.

This is an accidental-alias boundary, not protection against an adversarial
process replacing paths concurrently. Never follows links into old deliverables.
"""
from contextlib import contextmanager
import os
import stat

from .paths import local_absolute
from wechat_capture_v2.common import writer_lock as _writer_lock


def state_preflight(value, *, must_exist=True):
    state = local_absolute(value, allow_relative=True)
    if not state.exists():
        if must_exist:
            raise FileNotFoundError('next state must already exist')
        return state
    if not state.is_dir():
        raise ValueError('next state must be a directory')
    pending = [state]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                # DirEntry's Windows cached enumeration omits link counts.
                # An actual lstat is required to detect ordinary hardlinks.
                info = os.lstat(entry.path)
                if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                    raise ValueError('next state contains a link/reparse point')
                if stat.S_ISDIR(info.st_mode):
                    pending.append(entry.path)
                elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('next state contains a non-regular or hardlinked file')
    return state


@contextmanager
def writer_lock(value):
    state = state_preflight(value)
    with _writer_lock(state):
        yield
