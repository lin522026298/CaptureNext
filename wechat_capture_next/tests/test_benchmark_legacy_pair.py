from wechat_capture_next.tests import test_union_delivery as fixtures
from wechat_capture_next import benchmark_legacy_pair as benchmark,union_delivery,rolling_delivery
from wechat_capture_v2.common import digest_file
import unittest


class LegacyCutTests(unittest.TestCase):
    setUp=fixtures.UnionDeliveryTests.setUp
    tearDown=fixtures.UnionDeliveryTests.tearDown
    pages=fixtures.UnionDeliveryTests.pages
    publish=fixtures.UnionDeliveryTests.publish
    init_service=fixtures.UnionDeliveryTests.init_service
    prepared=fixtures.UnionDeliveryTests.prepared
    deliver=fixtures.UnionDeliveryTests.deliver
    def test_read_only_old_cut_can_seed_fresh_comparison_point_not_formal_adoption(self):
        self.prepared();backed=self.deliver();old=self.root/'old-restored'
        union_delivery.restore(self.state_repo,self.union_repo,backed['union_snapshot']['snapshot_id'],old)
        before={p:digest_file(p) for p in old.rglob('*') if p.is_file()}
        target=self.root/'new-comparison'
        result=benchmark.seed(old,self.state_repo,self.union_repo,self.formal/'OWNER.private.json',target)
        self.assertEqual(before,{p:digest_file(p) for p in old.rglob('*') if p.is_file()})
        self.assertFalse((old/'union/OWNER.private.json').exists())
        restored=rolling_delivery.restore(target,result['snapshot_id'],self.root/'new-restored')
        self.assertTrue(restored['attachments_closed']);self.assertFalse(restored['source_reconnected'])
