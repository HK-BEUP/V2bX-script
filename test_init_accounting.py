"""Private filesystem and fake-service tests; no production paths or panels."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import initconfig as wizard
from test_reconfigure import Service


class InitService(Service):
    def enable(self): self.calls.append('enable')


class AccountingInitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root/'etc/V2bX/config.json'
        self.service = InitService(self.path, running=False)
        self.config = wizard.make_config('https://panel.example', 'synthetic-secret', '406,407')
        self.leaf = self.root/self.config['Nodes'][0]['LegacyAccounting']['Directory'].lstrip('/')
        self.output = io.StringIO()

    def initialize(self, start=True, answer='YES'):
        replies = iter(['https://panel.example', '406,407', answer])
        with contextlib.redirect_stdout(self.output):
            return wizard.initialize(self.root, self.service, start=start,
                                     read=lambda _:next(replies), secret=lambda _:'synthetic-secret')

    def check_runtime_contract(self):
        saved = json.loads(self.path.read_text())
        for node in saved['Nodes']:
            directory = self.root/node['LegacyAccounting']['Directory'].lstrip('/')
            self.assertTrue(directory.is_dir())
            self.assertEqual(directory.resolve(), directory)
            self.assertEqual(directory.stat().st_uid, os.geteuid())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def assert_not_applied(self):
        self.assertFalse(self.path.exists())
        self.assertEqual(self.service.calls, [])
        self.assertNotIn('synthetic-secret', self.output.getvalue())

    def test_new_install_prepares_both_nodes_before_start_and_enable(self):
        self.service.on_start = self.check_runtime_contract
        self.initialize()
        self.assertEqual(self.service.calls, ['start', ('healthy', set()), 'enable'])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('synthetic-secret', self.output.getvalue())

    def test_save_only_prepares_directory_without_starting(self):
        self.initialize(start=False)
        self.check_runtime_contract()
        self.assertEqual(self.service.calls, [])

    def test_cancel_creates_no_accounting_or_config(self):
        self.initialize(answer='no')
        self.assert_not_applied()
        self.assertFalse((self.root/'var').exists())

    def test_existing_node_config_is_refused_before_provisioning(self):
        self.path.parent.mkdir(parents=True)
        original = json.dumps(self.config).encode(); self.path.write_bytes(original)
        with self.assertRaisesRegex(SystemExit, '已有节点配置'): self.initialize()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse((self.root/'var').exists())
        self.assertEqual(self.service.calls, [])

    def test_running_service_is_refused_before_provisioning(self):
        self.service.running = True
        with self.assertRaisesRegex(SystemExit, '服务运行中'): self.initialize()
        self.assert_not_applied()
        self.assertFalse((self.root/'var').exists())

    def test_existing_private_journal_is_preserved_byte_for_byte(self):
        self.leaf.mkdir(parents=True, mode=0o700)
        journal = self.leaf/'journal.json'; journal.write_bytes(b'synthetic-pending-ledger')
        before = (journal.read_bytes(), journal.stat().st_ino, journal.stat().st_mtime_ns)
        self.initialize()
        self.assertEqual((journal.read_bytes(), journal.stat().st_ino, journal.stat().st_mtime_ns), before)

    def test_loose_leaf_permissions_are_rejected_without_chmod(self):
        self.leaf.mkdir(parents=True); self.leaf.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, '0700'): self.initialize()
        self.assertEqual(self.leaf.stat().st_mode & 0o777, 0o755)
        self.assert_not_applied()

    def test_symlink_leaf_is_rejected_without_touching_destination(self):
        target = self.root/'unrelated'; target.mkdir()
        marker = target/'journal.json'; marker.write_bytes(b'keep-ledger')
        self.leaf.parent.mkdir(parents=True); self.leaf.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, '真实目录'): self.initialize()
        self.assertEqual(marker.read_bytes(), b'keep-ledger')
        self.assert_not_applied()

    def test_symlink_parent_is_rejected_before_creating_children(self):
        target = self.root/'unrelated'; target.mkdir()
        (self.root/'var').symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, '真实目录'): self.initialize()
        self.assertEqual(list(target.iterdir()), [])
        self.assert_not_applied()

    def test_regular_file_as_directory_is_rejected(self):
        self.leaf.parent.mkdir(parents=True); self.leaf.write_bytes(b'keep-file')
        with self.assertRaisesRegex(RuntimeError, '真实目录'): self.initialize()
        self.assertEqual(self.leaf.read_bytes(), b'keep-file')
        self.assert_not_applied()

    def test_writable_parent_is_rejected_without_permission_repair(self):
        parent = self.root/'var'; parent.mkdir(); parent.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, '写入权限不安全'): self.initialize()
        self.assertEqual(parent.stat().st_mode & 0o777, 0o777)
        self.assertEqual(list(parent.iterdir()), [])
        self.assert_not_applied()

    def test_foreign_owner_is_rejected_without_chown(self):
        with patch.object(wizard.os, 'geteuid', return_value=os.geteuid()+1):
            with self.assertRaisesRegex(RuntimeError, '所有者'): self.initialize()
        self.assert_not_applied()

    def test_unexpected_custom_new_path_is_refused(self):
        self.config['Nodes'][0]['LegacyAccounting']['Directory']='/var/lib/unrelated'
        with self.assertRaisesRegex(RuntimeError, '默认独立路径'):
            wizard.prepare_new_accounting(self.root, self.config['Nodes'])
        self.assertFalse((self.root/'var').exists())

    def test_failed_health_check_does_not_enable_or_delete_new_journal(self):
        self.service.accept = [False]
        self.service.on_start = lambda:(self.leaf/'journal.json').write_bytes(b'synthetic-new-batch')
        with self.assertRaisesRegex(RuntimeError, '监听检查'): self.initialize()
        self.assertNotIn('enable', self.service.calls)
        self.assertEqual((self.leaf/'journal.json').read_bytes(), b'synthetic-new-batch')
        self.assertTrue(self.path.exists())

    def test_concurrent_config_change_is_not_overwritten(self):
        self.path.parent.mkdir(parents=True)
        replies = iter(['https://panel.example','406'])
        def read(prompt):
            if '输入 YES' in prompt:
                self.path.write_bytes(b'operator-change'); return 'YES'
            return next(replies)
        with self.assertRaisesRegex(SystemExit, '配置已变化'), contextlib.redirect_stdout(self.output):
            wizard.initialize(self.root, self.service, read=read, secret=lambda _:'synthetic-secret')
        self.assertEqual(self.path.read_bytes(), b'operator-change')
        self.assertFalse((self.root/'var').exists())
        self.assertEqual(self.service.calls, [])


if __name__ == '__main__': unittest.main(verbosity=2)
