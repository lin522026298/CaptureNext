import hashlib
import unittest
from unittest.mock import patch
from wechat_capture_next.product import ProductCore
from wechat_capture_next.product_settings import DEFAULTS
from wechat_capture_next.tests import test_product as fixtures


class ProductPairedMemoTests(unittest.TestCase):
    setUp=fixtures.ProductTests.setUp
    tearDown=fixtures.ProductTests.tearDown
    pages=fixtures.ProductTests.pages
    publish=fixtures.ProductTests.publish
    init_service=fixtures.ProductTests.init_service
    prepared=fixtures.ProductTests.prepared
    wait=fixtures.ProductTests.wait

    def test_queue_keeps_private_memo_and_noop_does_not_add_recovery_points(self):
        self.prepared();paired=self.root/'paired'
        with patch('wechat_capture_next.product.preferences.load',return_value=dict(DEFAULTS,auto_capture=False)):
            core=ProductCore(self.state,self.root/'product',union_root=self.formal,repository_root=self.state_repo,
                union_repository=self.union_repo,paired_repository=paired)
        self.addCleanup(core.close);self.wait(core)
        first=self.wait(core,core.submit(dict(action='backup_pair')))
        self.assertFalse(first['result']['noop'])
        second=self.wait(core,core.submit(dict(action='backup_pair')))
        self.assertTrue(second['result']['repository_block_authentication_executed_now'])
        before=hashlib.sha256((paired/'repository.sqlite').read_bytes()).hexdigest()
        third=self.wait(core,core.submit(dict(action='backup_pair')))
        self.assertTrue(third['result']['reused_same_process_authenticated_repository_cut'])
        self.assertFalse(third['result']['repository_block_authentication_executed_now'])
        self.assertEqual(before,hashlib.sha256((paired/'repository.sqlite').read_bytes()).hexdigest())
        with patch('wechat_capture_next.product.preferences.load',return_value=dict(DEFAULTS,auto_capture=False)):
            core.close()
            restarted=ProductCore(self.state,self.root/'product',union_root=self.formal,repository_root=self.state_repo,
                union_repository=self.union_repo,paired_repository=paired)
        self.addCleanup(restarted.close);self.wait(restarted)
        cold=self.wait(restarted,restarted.submit(dict(action='backup_pair')))
        self.assertTrue(cold['result']['repository_block_authentication_executed_now'])
        self.assertFalse(cold['result']['reused_same_process_authenticated_repository_cut'])


if __name__=='__main__':unittest.main()
