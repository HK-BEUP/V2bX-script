import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('gha', Path(__file__).with_name('gha_amd64.py'))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class GuardTests(unittest.TestCase):
    def env(self):
        return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': g.REPO, 'GITHUB_REF': g.BRANCH}

    def test_only_designated_runner_allowed(self):
        g.guard(self.env(), 'Linux', 'x86_64', 'systemd')

    def test_local_or_other_repo_or_master_refused(self):
        for key, value in [('GITHUB_ACTIONS', ''), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                           ('GITHUB_REPOSITORY', 'other/repo'), ('GITHUB_REF', 'refs/heads/master')]:
            env = self.env() | {key: value}
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                g.guard(env, 'Linux', 'x86_64', 'systemd')

    def test_arm64_or_emulated_container_not_claimed_native(self):
        for values in [('Darwin', 'arm64', 'launchd'), ('Linux', 'aarch64', 'systemd'),
                       ('Linux', 'x86_64', 'python3')]:
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                g.guard(self.env(), *values)

    def test_existing_proxy_refused_before_systemctl(self):
        with patch.object(Path, 'exists', return_value=True), \
                patch.object(g.subprocess, 'run') as run, self.assertRaises(RuntimeError):
            g.fresh()
        run.assert_not_called()

    def test_existing_unit_refused(self):
        with patch.object(Path, 'exists', return_value=False), patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(g.subprocess, 'run') as run, self.assertRaises(RuntimeError):
            run.return_value.stdout = 'loaded\n'
            g.fresh()

    def test_wrong_patch_hash_refused_before_archive_open(self):
        with patch.object(g, 'sha', return_value='0' * 64), \
                patch.object(g.zipfile, 'ZipFile') as archive, self.assertRaises(RuntimeError):
            g.inspect_patch(Path('/synthetic.zip'))
        archive.assert_not_called()

    def test_only_sanitized_result_readable_under_private_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            secret = temp / 'synthetic-private.json'
            old = os.umask(0o077)
            try:
                g.save(secret, {'synthetic': True})
                g.export_result(temp, {'ok': True, 'checks': []})
            finally:
                os.umask(old)
            self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((temp / 'beup-observation-results/systemd.json').stat().st_mode), 0o644)


if __name__ == '__main__':
    unittest.main()
