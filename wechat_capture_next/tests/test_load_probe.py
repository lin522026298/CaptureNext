from argparse import Namespace
from contextlib import closing, redirect_stdout
import io
import json
import unittest

from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_next.load_probe import worker, validate_measurement_output


class ProbeTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def test_logs_cannot_pollute_measured_state_or_source_or_managed_target(self):
        with closing(self.init_service()) as service:
            for bad in (service.state/'logs', service.root/'logs', self.root/'managed'/'logs', self.root):
                with self.subTest(path=bad), self.assertRaises(ValueError):
                    validate_measurement_output(Namespace(state=service.state, out=bad, managed=self.root/'managed'))
            self.assertEqual(validate_measurement_output(Namespace(state=service.state, out=self.root/'logs',
                managed=self.root/'managed')), self.root/'logs')

    def test_watch_and_sync_close_before_final_size_and_keep_original_fields(self):
        with closing(self.init_service()) as service:
            state = service.state
        out = self.root/'measurement'
        out.mkdir()
        for action in ('watch', 'sync'):
            with self.subTest(action=action), redirect_stdout(io.StringIO()) as text:
                worker(Namespace(state=state, out=out, action=action, seconds=0,
                    managed=self.root/'managed' if action == 'sync' else None, verify=True))
                rows = [json.loads(line) for line in text.getvalue().splitlines()]
                self.assertEqual(rows[0]['event'], 'start')
                self.assertEqual(rows[-1]['event'], 'end')
                self.assertTrue(all(value[0] == 0 for value in rows[-1]['checkpoint'].values()))
                self.assertFalse((state/'catalog.sqlite-wal').exists())
                if action == 'watch':
                    self.assertEqual(rows[1]['report']['summary']['active_messages'], 40)
                else:
                    self.assertEqual(rows[1]['result']['added_observations'], 40)
