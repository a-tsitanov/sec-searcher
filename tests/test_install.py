"""Installer control flow without Docker, downloads or model inference."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

INSTALL = Path(__file__).resolve().parents[1] / 'install.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source with spaces'
        for name in ['pyproject.toml', 'uv.lock', 'Dockerfile', 'compose.yaml', 'src/sec_searcher/api.py']:
            p = self.source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.touch()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'commands'
        self.stub('docker', 'echo "$*" >> "$INSTALL_LOG"\nexit "${DOCKER_EXIT:-0}"')
        self.stub('curl', 'echo unexpected-download >> "$INSTALL_LOG"\nexit 99')
        self.env = dict(os.environ, PATH=f'{self.bin}:/usr/bin:/bin', INSTALL_LOG=str(self.log))

    def stub(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/bash\n' + body + '\n')
        p.chmod(0o755)

    def run_install(self, *args, piped=False):
        command = ['bash', '-s', '--'] if piped else ['bash', str(INSTALL)]
        return subprocess.run(command + ['--source-dir', str(self.source), *args],
                              input=INSTALL.read_text() if piped else None,
                              text=True, capture_output=True, env=self.env, timeout=10)

    def test_piped_build_only(self):
        result = self.run_install('--build-only', piped=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text()
        self.assertIn('compose build app', log)
        self.assertNotIn('up -d', log)
        self.assertFalse((self.source / 'models').exists())

    def test_custom_model_repeated_install_preserves_env(self):
        (self.source / 'models').mkdir()
        (self.source / 'models/custom.gguf').write_bytes(b'existing model')
        (self.source / '.env').write_text('KEEP=value\n')
        for _ in range(2):
            result = self.run_install('--model-file', 'custom.gguf', '--no-download')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.source / '.env').read_text(), 'KEEP=value\n')
        self.assertEqual((self.source / '.env.install').read_text(), 'MODEL_FILE=custom.gguf\n')
        self.assertIn('--env-file .env.install up -d --wait', self.log.read_text())
        self.assertNotIn('unexpected-download', self.log.read_text())

    def test_missing_model_does_not_start(self):
        result = self.run_install('--no-download')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('up -d', self.log.read_text())

    def test_checksum_mismatch_does_not_start(self):
        (self.source / 'models').mkdir()
        (self.source / 'models/Qwen3.6-35B-A3B-UD-Q3_K_M.gguf').write_bytes(b'wrong')
        result = self.run_install('--no-download')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256 mismatch', result.stderr)
        self.assertNotIn('up -d', self.log.read_text())

    def test_download_is_promoted_only_after_checksum(self):
        self.stub('curl', 'while [[ $# -gt 0 ]]; do if [[ "$1" == --output ]]; then printf weights > "$2"; exit 0; fi; shift; done; exit 1')
        self.stub('sha256sum', 'echo "1b715841683f960bd9a49f008181bd910ee169b78d4cf465b6fde7f4d929ff99  $1"')
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        model = self.source / 'models/Qwen3.6-35B-A3B-UD-Q3_K_M.gguf'
        self.assertEqual(model.read_bytes(), b'weights')
        self.assertFalse(Path(str(model) + '.part').exists())
        self.assertIn('up -d --wait', self.log.read_text())

    def test_docker_failure_stops_install(self):
        self.env['DOCKER_EXIT'] = '1'
        result = self.run_install('--build-only')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('compose build', self.log.read_text())

    def test_invalid_model_path(self):
        result = self.run_install('--model-file', '../bad.gguf')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())
