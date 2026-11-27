import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from entra_reference import prepare as prepare_profile
from entra_worker import provider_factory
from execution_plan import prepare, register
from lab_worker import run_claimed
from ledger import ContractError, Ledger
from management import Management
from mounted_secret import MountedSecret, filename, grant_for
from spool import LocalSpool


class EntraWorkerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        self.profile = prepare_profile('env-a', 'source-a', {
            'dataset': 'signins', 'credential_ref': 'key', 'interval_seconds': 300,
            'tenant_id': '11111111-1111-1111-1111-111111111111',
            'client_id': '22222222-2222-2222-2222-222222222222',
            'initial': '2026-11-01T00:00:00Z', 'lag_seconds': 600})
        self.plan = prepare('env-a', 'source-a', 'signins', self.profile.source.revision,
                            'v1', 'b'*64, 300)
        self.reader = MountedSecret(base, self.plan, 'key', os.getuid())
        secret_file = base / filename(grant_for(self.plan, 'key'))
        secret_file.write_text('dummy-secret')
        secret_file.chmod(0o400)
        self.m = Management(base / 'm.db', 'env-a')
        self.ledger = Ledger(base / 'l.db', self.plan.ledger_scope())
        self.spool = LocalSpool(base / 's.db', self.plan.ledger_scope())
        for store in (self.m, self.ledger, self.spool):
            self.addCleanup(store.close)
        register(self.m, self.plan, 'operator', 100)
        self.m.change('source-a', 'signins', 0, 'admit_lab', 'operator', 100, 'c'*64)
        self.claim = self.m.claim('worker', 100)
        self.resolve = Mock(return_value=['8.8.8.8'])
        self.clock = lambda: datetime(2026, 11, 1, 1, 10, tzinfo=timezone.utc)

    def build(self):
        return provider_factory(self.profile, self.reader, self.resolve, self.clock)

    def test_wrong_provider_revision_rejected_before_dns(self):
        wrong = prepare('env-a', 'source-a', 'signins', 'f'*64, 'v1', 'b'*64, 300)
        with self.assertRaises(ContractError):
            self.build()(wrong)
        self.resolve.assert_not_called()

    @patch('graph_transport._PinnedConnection')
    @patch('microsoft_transport.PinnedHTTPS')
    @patch('microsoft_transport.public_ip', return_value='8.8.8.8')
    def test_full_managed_collection_with_fake_http(self, dns, oauth, graph):
        for connection, body in ((oauth, b'{"access_token":"dummy-token","token_type":"Bearer"}'),
            (graph, json.dumps({'value': [{'id': 'event-1', 'createdDateTime': '2026-11-01T00:20:00Z'}]}).encode())):
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.getheader.side_effect = lambda key, default=None: default
            response.read.return_value = body
        result = run_claimed(self.m, self.plan, self.claim, 'worker', lambda: 101,
                             self.ledger, self.spool, self.build())
        self.assertEqual((result.status, result.acknowledged_events, result.boundary),
                         ('complete', 1, 'local_spool'))
        self.assertEqual(self.spool.read()[0][1]['events'][0]['payload']['id'], 'event-1')
        self.assertIn(b'client_secret=dummy-secret', oauth.return_value.request.call_args.kwargs['body'])
        self.assertEqual(graph.return_value.request.call_args.kwargs['headers']['Authorization'], 'Bearer dummy-token')
        self.assertEqual(self.m.health_snapshot(101)['sources'][0]['last_run']['acknowledged_events'], 1)
        self.assertFalse(self.m.health_snapshot(101)['native_delivery_qualified'])


if __name__ == '__main__':
    unittest.main()
