"""No silent sensitive-backup opt-in when loading old preferences."""
import json
from pathlib import Path
import tempfile
import unittest

from wechat_capture_next import product_settings as settings


class SettingsCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'settings.json'

    def write(self,value):
        self.path.write_text(json.dumps(value),encoding='utf-8')
        return self.path.read_bytes()

    def test_new_and_exact_old_defaults_do_not_include_secrets_or_write(self):
        self.assertFalse(settings.load(self.path)['backup_include_secrets'])
        self.assertFalse(self.path.exists())
        old={k:v for k,v in settings.DEFAULTS.items() if k!='backup_include_secrets'}
        before=self.write(old)
        self.assertEqual(settings.load(self.path),settings.DEFAULTS)
        self.assertEqual(self.path.read_bytes(),before)
        with self.assertRaises(ValueError):settings.validate(old)

    def test_new_explicit_value_roundtrips_without_read_writes(self):
        value=dict(settings.DEFAULTS,backup_include_secrets=True)
        settings.save(self.path,value);before=self.path.read_bytes()
        self.assertEqual(settings.load(self.path),value)
        self.assertEqual(self.path.read_bytes(),before)
        self.assertFalse(settings.save(self.path,value))

    def test_unknown_missing_and_wrong_types_fail_closed_unchanged(self):
        old={k:v for k,v in settings.DEFAULTS.items() if k!='backup_include_secrets'}
        for value in (dict(old,future_option=True),{k:v for k,v in old.items() if k!='auto_capture'},
                      dict(old,auto_capture=1),dict(settings.DEFAULTS,backup_include_secrets=1),
                      dict(settings.DEFAULTS,backup_include_secrets='true')):
            with self.subTest(value=value):
                before=self.write(value)
                with self.assertRaises(ValueError):settings.load(self.path)
                self.assertEqual(self.path.read_bytes(),before)
