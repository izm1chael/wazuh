import os
import tempfile
import unittest
from pathlib import Path

from execution_plan import prepare
from ledger import ContractError
from mounted_secret import MountedSecret, filename, grant_for


def plan(**changes):
    return prepare(**{'environment': 'env-a', 'instance': 'source-a', 'dataset': 'signins',
                      'provider_revision': 'a'*64, 'credential_generation': 'v1',
                      'content_revision': 'b'*64, 'interval': 300, **changes})


class MountedSecretTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = plan()
        self.reader = MountedSecret(self.root, self.plan, 'key', os.getuid())
        self.file = self.root / filename(grant_for(self.plan, 'key'))

    def write(self, data=b'dummy-secret', mode=0o400):
        self.file.write_bytes(data)
        self.file.chmod(mode)

    def test_read_and_exact_scope_generation(self):
        self.write()
        self.assertEqual(self.reader.resolve(self.plan, 'key'), 'dummy-secret')
        for p in (plan(environment='env-b'), plan(instance='source-b'),
                  plan(credential_generation='v2'), plan(content_revision='c'*64)):
            with self.assertRaisesRegex(ContractError, '^credential grant mismatch$'):
                self.reader.resolve(p, 'key')
        with self.assertRaises(ContractError):
            self.reader.resolve(self.plan, 'other')
        self.assertNotEqual(filename(grant_for(self.plan, 'key')), filename(grant_for(plan(credential_generation='v2'), 'key')))

    def test_permissions_and_size(self):
        for data, mode in ((b'dummy', 0o644), (b'', 0o400), (b'x'*4097, 0o400),
                           (b'line\n', 0o400), (b'\xff', 0o400)):
            with self.subTest(data_length=len(data), mode=mode):
                self.file.unlink(missing_ok=True)
                self.write(data, mode)
                with self.assertRaisesRegex(ContractError, '^credential unavailable$'):
                    self.reader.resolve(self.plan, 'key')

    def test_symlink_hardlink_and_fifo_rejected(self):
        target = self.root / 'target'
        target.write_text('dummy')
        target.chmod(0o400)
        self.file.symlink_to(target)
        with self.assertRaises(ContractError):
            self.reader.resolve(self.plan, 'key')
        self.file.unlink()
        os.link(target, self.file)
        with self.assertRaises(ContractError):
            self.reader.resolve(self.plan, 'key')
        self.file.unlink()
        os.mkfifo(self.file, 0o400)
        with self.assertRaises(ContractError):
            self.reader.resolve(self.plan, 'key')

    def test_bad_directory_and_owner_rejected(self):
        self.write()
        self.root.chmod(0o755)
        with self.assertRaises(ContractError):
            self.reader.resolve(self.plan, 'key')
        self.root.chmod(0o700)
        with self.assertRaises(ContractError):
            MountedSecret(self.root, self.plan, 'key', os.getuid()+1).resolve(self.plan, 'key')
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ContractError):
            MountedSecret(link, self.plan, 'key', os.getuid()).resolve(self.plan, 'key')

    def test_missing_redacted_and_no_path_from_reference(self):
        with self.assertRaisesRegex(ContractError, '^credential unavailable$'):
            self.reader.resolve(self.plan, 'key')
        with self.assertRaises(ContractError):
            grant_for(self.plan, '../secret')


if __name__ == '__main__':
    unittest.main()
