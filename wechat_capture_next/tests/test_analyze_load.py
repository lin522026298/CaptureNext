from contextlib import closing
import json
import sqlite3
import unittest

from wechat_capture_next.analyze_load import analyze, quantiles
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_v2.tests.test_backend import TABLE


class AnalyzeTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    pages = fixtures.ServiceTests.pages
    publish = fixtures.ServiceTests.publish
    init_service = fixtures.ServiceTests.init_service

    def test_cohort_uses_recorded_ids_not_current_catalog_totals(self):
        with closing(self.init_service()) as service:
            report = service.capture(force=True)
            with closing(sqlite3.connect(self.plain)) as db, db:
                db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1', ('after-trial',))
            self.publish()
            service.capture(force=True)
            trial = self.root/'trial'
            trial.mkdir()
            end = dict(whole_worker_seconds=10, cpu_seconds=2, logical_write_bytes=100, logical_read_bytes=200,
                unix=20, settled_before={'buckets': {'catalog.sqlite':100}}, settled_after={'buckets':{'catalog.sqlite':120}})
            (trial/'RESULT.json').write_text(json.dumps(dict(returncode=0,
                events=dict(cycles=1,idle=0,partial=0,new_versions=40),endpoints={'start':{'unix':10},'end':end})),encoding='utf-8')
            (trial/'cycles.private.jsonl').write_text(json.dumps(dict(event='cycle',report=report,unix=20,
                logical_write_bytes=100))+'\n',encoding='utf-8')
            with (trial/'samples.jsonl').open('w',encoding='utf-8') as stream:
                for baseline, rate in ((True,999),(False,0),(False,10)):
                    stream.write(json.dumps(dict(private_bytes=20,rss_bytes=30,
                        logical_write_bytes_per_second=rate,first_counter_baseline=baseline))+'\n')
            summary = analyze(trial,service.state)
            self.assertEqual(summary['measured_cohort']['version']['rows'],40)
            self.assertEqual(service.catalog.summary()['versions'],41)
            self.assertEqual(summary['measured_cohort']['transitions'],{'new':40})
            self.assertEqual(summary['sampled_quantiles']['logical_write_bytes_per_second']['max'],10)
            self.assertEqual(summary['state_bucket_growth_bytes'],{'catalog.sqlite':20})
            self.assertEqual(summary['cpu_one_core_percent'],20)
            self.assertEqual(summary['mean_logical_write_bytes_per_second'],10)
            log = trial/'cycles.private.jsonl'
            log.write_text(log.read_text(encoding='utf-8')*2,encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'duplicate'):
                analyze(trial,service.state)

    def test_nearest_rank_quantiles_and_empty_samples(self):
        self.assertEqual(quantiles([]),{})
        self.assertEqual(quantiles([4,1,3,2]),{'p50':2,'p95':4,'p99':4,'max':4})


if __name__ == '__main__':
    unittest.main()
