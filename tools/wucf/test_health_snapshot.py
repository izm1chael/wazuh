import tempfile
import unittest
from pathlib import Path

from ledger import ContractError
from management import Management
from runtime import RunResult


class HealthSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'management.db'
        self.m = Management(self.path, 'env-a')
        self.addCleanup(lambda: self.m.close())
        self.m.register('a', 'signins', 'a'*64, 300, 'operator', 100)
        self.m.change('a', 'signins', 0, 'admit_lab', 'operator', 100, 'b'*64)

    def source(self, now):
        snapshot = self.m.health_snapshot(now)
        self.assertEqual(snapshot['coverage'], 'unknown')
        self.assertFalse(snapshot['native_delivery_qualified'])
        self.assertEqual(snapshot['delivery_boundary'], 'local_spool')
        return snapshot['sources'][0]

    def finish(self, job, result, now):
        return self.m.finish('a', 'signins', job['lease'], 'worker', now,
                             result.status, result.boundary, result=result)

    def test_persisted_counts_and_overdue(self):
        self.assertEqual(self.source(100)['status'], 'not_observed')
        job = self.m.claim('worker', 100)
        self.assertEqual(self.source(100)['status'], 'collecting')
        self.finish(job, RunResult('complete', 1, 5, False, 'local_spool'), 101)
        self.m.close()
        self.m = Management(self.path, 'env-a')
        source = self.source(101)
        self.assertEqual(source['status'], 'local_observation')
        self.assertEqual(source['last_run']['acknowledged_events'], 5)
        self.assertNotIn('lease', source)
        self.assertEqual(self.source(702)['status'], 'overdue')

    def test_invalid_counts_roll_back_and_expiry_visible(self):
        job = self.m.claim('worker', 100, 30)
        with self.assertRaises(ContractError):
            self.finish(job, RunResult('complete', 1, 101, False, 'local_spool'), 101)
        self.assertEqual(self.source(101)['status'], 'collecting')
        self.assertIsNone(self.source(101)['last_run'])
        self.assertEqual(self.source(130)['status'], 'expired_claim')

    def test_delivery_failure_and_legacy_completion(self):
        job = self.m.claim('worker', 100)
        state = self.finish(job, RunResult('delivery_unknown', 1, 1, True, 'local_spool'), 101)
        self.assertEqual(self.source(101)['status'], 'review')
        self.assertTrue(self.source(101)['last_run']['pending'])
        paused = self.m.change('a', 'signins', state['version'], 'reconcile', 'operator', 102, 'c'*64)
        self.m.change('a', 'signins', paused['version'], 'resume_lab', 'operator', 103)
        self.assertEqual(self.source(103)['status'], 'not_observed')
        job = self.m.claim('worker', 103)
        self.m.finish('a', 'signins', job['lease'], 'worker', 104, 'idle', 'local_spool')
        self.assertIsNone(self.source(104)['last_run'])


if __name__ == '__main__':
    unittest.main()
