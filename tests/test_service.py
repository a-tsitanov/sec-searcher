import io
import json
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from sec_searcher.archives import extract_project
from sec_searcher.scanner import LlamaCpp, chunks, collect_files, validate_findings
from sec_searcher.service import State
from sec_searcher.api import create_app
from fastapi.testclient import TestClient


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buf.getvalue()


FINDING = {'title': 'Command injection', 'severity': 'high', 'line': 2,
           'description': 'User input reaches a shell.', 'recommendation': 'Avoid shell execution.', 'cwe': 'CWE-78'}


class ClientConfigurationTests(unittest.TestCase):
    def test_container_hostname_and_invalid_authorities(self):
        self.assertEqual(LlamaCpp(host='llama').base, 'http://llama:8080')
        self.assertEqual(LlamaCpp(8081, host='host.docker.internal').base,
                         'http://host.docker.internal:8081')
        for host in ('http://llama', 'llama/path', 'user@llama', 'llama:8080', '', 'llama\n'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                LlamaCpp(host=host)
        for port in (0, 65536, True, '8080'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                LlamaCpp(port)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / 'project'

    def test_structure_and_file_selection(self):
        data = make_zip([('app/src/main.py', 'print(1)'), ('app/node_modules/pkg/a.js', 'x'),
                         ('app/.env', 'SECRET=x'), ('app/logo.png', b'\x00'), ('app/empty.py', ''),
                         ('app/invalid.py', b'\xff'), ('app/long.js', 'x' * 7000)])
        self.assertEqual(extract_project(data, self.target), 7)
        files, skipped = collect_files(self.target)
        self.assertEqual(files, [('app/src/main.py', 'print(1)')])
        self.assertEqual(len(skipped), 6)

    def test_reject_escaping_paths(self):
        for name in ['../escape.py', '/tmp/escape.py', 'a/../../escape.py', 'C:/escape.py', 'a\\escape.py']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                extract_project(make_zip([(name, 'x')]), self.target)
            self.assertFalse(self.target.exists())

    def test_reject_symlink(self):
        item = zipfile.ZipInfo('link.py')
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError):
            extract_project(make_zip([(item, '/etc/passwd')]), self.target)

    def test_reject_case_collisions(self):
        with self.assertRaises(ValueError):
            extract_project(make_zip([('A.py', 'one'), ('a.py', 'two')]), self.target)

    def test_limits_and_corruption(self):
        with patch('sec_searcher.archives.MAX_UNPACKED', 100), self.assertRaises(ValueError):
            extract_project(make_zip([('big.py', 'x' * 101)]), self.target)
        with patch('sec_searcher.archives.MAX_ENTRIES', 1), self.assertRaises(ValueError):
            extract_project(make_zip([('a.py', 'x'), ('b.py', 'x')]), self.target)
        with self.assertRaises(ValueError):
            extract_project(b'not a zip', self.target)
        self.assertFalse(self.target.exists())


class ScannerTests(unittest.TestCase):
    def test_chunks_cover_all_lines_with_real_numbers(self):
        source = '\n'.join('x' * 90 for _ in range(600))
        covered = set()
        for start, end, content in chunks(source):
            self.assertLessEqual(len(content), 12000)
            self.assertTrue(content.startswith(f'{start}: '))
            covered.update(range(start, end + 1))
        self.assertEqual(covered, set(range(1, 601)))

    def test_invalid_model_output_is_error(self):
        for value in [{'findings': [{}]}, {'findings': [FINDING | {'line': 500}]},
                      {'findings': [FINDING | {'line': True}]}, {'findings': [FINDING | {'severity': 'safe'}]}, {}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_findings(value, 'file.py', 1, 10)


class FakeLlamaHandler(BaseHTTPRequestHandler):
    mode = 'ok'
    received = []

    def log_message(self, *args):
        pass

    def send_json(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        assert self.path == '/v1/models'
        self.send_json({'data': [{'id': 'local-test'}]})

    def do_POST(self):
        assert self.path == '/v1/chat/completions'
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.received.append(body)
        content = 'invalid JSON' if self.mode == 'invalid' else json.dumps({'findings': [FINDING]})
        self.send_json({'choices': [{'finish_reason': 'length' if self.mode == 'truncated' else 'stop',
                                    'message': {'content': content}}]})


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        FakeLlamaHandler.mode = 'ok'
        FakeLlamaHandler.received = []
        self.llama = ThreadingHTTPServer(('127.0.0.1', 0), FakeLlamaHandler)
        self.state = State(LlamaCpp(self.llama.server_port), default_mode='files')
        threading.Thread(target=self.llama.serve_forever, daemon=True).start()
        self.client = TestClient(create_app(self.state), base_url='http://127.0.0.1:8765')
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.llama.shutdown()
        self.llama.server_close()
        self.assertFalse(Path(self.state.storage.name).exists())

    def request(self, path, data=None, headers=None):
        headers = dict(headers or {})
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
        response = self.client.request('GET' if data is None else 'POST', path, content=data, headers=headers)
        if response.is_error:
            raise urllib.error.HTTPError(str(response.url), response.status_code, response.text, response.headers, None)
        return response.json()

    def run_scan(self):
        token = self.request('/api/config')['token']
        headers = {'X-CSRF-Token': token, 'Content-Type': 'application/zip'}
        archive = make_zip([('project/src/app.py', 'import os\nos.system(user_input)\n'), ('project/node_modules/x.js', 'x')])
        upload = self.request('/api/upload', archive, headers)
        self.request('/api/scan', {'project_id': upload['project_id'], 'model': 'local-test'}, {'X-CSRF-Token': token})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            report = self.request('/api/scan')
            if report['status'] != 'running':
                return report
            time.sleep(.02)
        self.fail('Scan did not finish')

    def test_zip_to_report_over_http(self):
        report = self.run_scan()
        self.assertEqual(report['status'], 'done')
        self.assertEqual(report['successful'], 1)
        self.assertEqual(report['findings'][0]['file'], 'project/src/app.py')
        self.assertEqual(len(report['skipped']), 1)
        payload = FakeLlamaHandler.received[0]
        self.assertEqual(payload['response_format']['type'], 'json_object')
        self.assertFalse(payload['stream'])

    def test_bad_model_reply_is_not_clean_scan(self):
        for mode in ['invalid', 'truncated']:
            FakeLlamaHandler.mode = mode
            report = self.run_scan()
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(report['successful'], 0)
            self.assertEqual(len(report['errors']), 1)

    def test_csrf_origin_and_host(self):
        attempts = [('/api/cancel', {}, {}), ('/api/config', None, {'Host': 'evil.test'}),
                    ('/api/config', None, {'Origin': 'https://evil.test'})]
        for path, data, headers in attempts:
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as result:
                self.request(path, data, headers)
            self.assertEqual(result.exception.code, 403)
            result.exception.close()

    def test_fastapi_validation_and_request_limits(self):
        headers = {'X-CSRF-Token': self.state.token, 'Content-Type': 'application/json'}
        response = self.client.post('/api/scan', content='{"project_id":"x","model":42}', headers=headers)
        self.assertEqual(response.status_code, 422)
        self.assertIn('error', response.json())
        response = self.client.post('/api/scan', content='[1]', headers=headers)
        self.assertEqual(response.status_code, 422)
        response = self.client.post('/api/cancel', content='{' , headers=headers)
        self.assertEqual(response.status_code, 422)
        response = self.client.post('/api/cancel', content='x' * 8193, headers=headers)
        self.assertEqual(response.status_code, 413)
        with patch('sec_searcher.api.MAX_UPLOAD', 10):
            response = self.client.post('/api/upload', content=iter([b'x' * 6, b'y' * 6]),
                                        headers={**headers, 'Content-Type': 'application/zip'})
            self.assertEqual(response.status_code, 413)
        response = self.client.post('/api/upload', content=b'zip', headers=headers)
        self.assertEqual(response.status_code, 415)

    def test_packaged_static_files_and_schema(self):
        for path in ('/', '/app.js', '/style.css'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        schema = self.client.get('/openapi.json').json()
        self.assertIn('ScanRequest', schema['components']['schemas'])
        self.assertEqual(self.client.get('/api/scan').json(), None)

    def test_only_uploaded_project_can_be_scanned(self):
        with self.assertRaises(ValueError):
            self.state.start('../../etc', 'local-test')

    def test_cancellation_before_review(self):
        upload = self.state.upload(make_zip([('a.py', 'x')]))
        entered, release = threading.Event(), threading.Event()
        def wait_for_cancel(model):
            entered.set()
            release.wait(3)
        with patch.object(self.state.client, 'ensure_local', wait_for_cancel):
            self.state.start(upload['project_id'], 'local-test')
            self.assertTrue(entered.wait(2))
            with self.assertRaises(ValueError):
                self.state.upload(make_zip([('b.py', 'x')]))
            self.state.cancel.set()
            release.set()
            deadline = time.monotonic() + 3
            while self.state.snapshot()['status'] == 'running' and time.monotonic() < deadline:
                time.sleep(.02)
        self.assertEqual(self.state.snapshot()['status'], 'cancelled')
        self.assertEqual(FakeLlamaHandler.received, [])


if __name__ == '__main__':
    unittest.main()
