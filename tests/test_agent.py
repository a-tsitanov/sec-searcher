"""Real Deep Agents + scripted local HTTP model. These test mechanics, not LLM quality."""
import json
import tempfile
import threading
import unittest
import hashlib
import zipfile
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sec_searcher.agent_scan import ProjectView, scan_agent
from sec_searcher.scanner import LlamaCpp

FIXTURES = Path(__file__).parent / 'fixtures'


class ScriptedModel(BaseHTTPRequestHandler):
    mode = 'vulnerable'
    requests = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        type(self).requests.append(request)
        outputs = [m for m in request['messages'] if m['role'] == 'tool' or
                   (m['role'] == 'user' and isinstance(m.get('content'), str) and m['content'].startswith('{"tool_result":'))]
        step = len(outputs)
        evidence = [
            {'file': 'repository.py', 'start_line': 6, 'end_line': 7},
            {'file': 'routes.py', 'start_line': 9, 'end_line': 10},
        ]
        finding = {'title': 'SQL injection', 'severity': 'high', 'cwe': 'CWE-89',
                   'description': 'HTTP input flows into concatenated SQL across two files.',
                   'recommendation': 'Bind parameters.', 'evidence': evidence}
        if self.mode == 'invalid_evidence' or (self.mode == 'retracted' and step == 4):
            finding['evidence'][0]['end_line'] = 999
        calls = [('list_project_files', {}), ('search_project', {'query': 'find_users'}),
                 ('read_project_file', {'path': 'routes.py', 'start_line': 1, 'end_line': 100}),
                 ('read_project_file', {'path': 'repository.py', 'start_line': 1, 'end_line': 100})]
        if self.mode == 'denied':
            calls = [('read_file', {'file_path': '/etc/passwd'}), ('task', {'description': 'read host', 'subagent_type': 'general-purpose'})]
        if self.mode == 'long':
            calls = [('read_project_file', {'path': f'part_{i}.py'}) for i in range(35)] + [('read_project_file', {'path': 'repository.py'}),
                ('read_project_file', {'path': 'routes.py'})]
        if self.mode == 'graph':
            calls = [('graph_symbols', {'query': 'find_users'}),
                     ('graph_neighbors', {'symbol_id': 'repository_find_users'}),
                     ('graph_path', {'source_id': 'routes_users', 'target_id': 'repository_find_users'})] + calls
        if self.mode == 'early':
            calls = []
        if self.mode in {'saved_loop', 'saved_finish', 'saved_failure', 'saved_auto_finish'}:
            calls.append(('save_finding', {'finding': finding}))
            if self.mode in {'saved_loop', 'saved_auto_finish'}:
                calls += [('read_project_file', {'path': 'routes.py'})] * 30
        name, args = calls[step] if step < len(calls) else ('submit_report', {
            'findings': [] if self.mode in {'safe', 'saved_finish'} or (self.mode == 'retracted' and step > 4) else [finding], 'summary': 'Checked HTTP to SQL flow.', 'limitations': []})
        if self.mode in {'saved_auto_finish', 'report_only'}:
            names = {t['function']['name'] for t in request.get('tools', [])}
            if 'response_format' in request:
                names = {t['properties']['name']['enum'][0] for t in request['response_format']['schema']['anyOf']}
            if names == {'submit_report'}:
                name, args = 'submit_report', {'findings': [], 'summary': 'Сохранённые находки проверены по цитатам.', 'limitations': []}
            elif names == {'save_finding', 'submit_report'}:
                name, args = 'save_finding', {'finding': finding}
        message = {'role': 'assistant', 'content': None, 'tool_calls': [
            {'id': f'call_{step}', 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(args)}}]}
        if self.mode == 'prose' or (self.mode == 'saved_failure' and step >= 5):
            message = {'role': 'assistant', 'content': 'Looks safe.'}
        json_protocol = 'response_format' in request
        if json_protocol:
            message = {'role': 'assistant', 'content': json.dumps({'name': name, 'arguments': args})}
        body = {'id': 'chatcmpl-test', 'object': 'chat.completion', 'created': 1, 'model': 'scripted',
                'choices': [{'index': 0, 'message': message, 'finish_reason': 'stop' if self.mode == 'prose' or json_protocol else 'tool_calls'}],
                'usage': {'prompt_tokens': 1000, 'completion_tokens': 100, 'total_tokens': 1100}}
        if self.mode == 'truncated':
            body['choices'][0]['finish_reason'] = 'length'
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class AgentTests(unittest.TestCase):
    def test_output_budget_reaches_local_model(self):
        report = self.run_agent(protocol='json', max_output_tokens=6144)
        self.assertEqual(report['report_source'], 'model')
        self.assertEqual(report['max_output_tokens'], 6144)
        self.assertTrue(all(r['max_tokens'] == 6144 for r in ScriptedModel.requests))

    def test_truncated_json_is_not_accepted_as_finished_report(self):
        report = self.run_agent('truncated', protocol='json', max_output_tokens=8192)
        self.assertEqual(report['report_source'], 'service')
        self.assertTrue(any('finish_reason=length' in e['error'] and '8192' in e['error'] for e in report['errors']))

    def setUp(self):
        ScriptedModel.requests = []
        ScriptedModel.mode = 'vulnerable'
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), ScriptedModel)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.report = {'findings': [], 'errors': [], 'events': []}

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()

    def update(self, **values):
        for key, value in values.items():
            if key.startswith('add_'):
                self.report[key[4:]].extend(value)
            else:
                self.report[key] = value

    def run_agent(self, mode='vulnerable', **kwargs):
        ScriptedModel.mode = mode
        project = FIXTURES / ('safe' if mode == 'safe' else 'vulnerable')
        kwargs.setdefault('protocol', 'native')
        if mode == 'long':
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory)
                for source in project.glob('*.py'):
                    (target / source.name).write_bytes(source.read_bytes())
                for i in range(35):
                    (target / f'part_{i}.py').write_text('x=1\n')
                scan_agent(target, 'scripted', LlamaCpp(self.http.server_port), self.update, lambda: False, **kwargs)
        else:
            scan_agent(project, 'scripted', LlamaCpp(self.http.server_port), self.update, lambda: False, **kwargs)
        return self.report

    def test_cross_file_agent_loop(self):
        report = self.run_agent()
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(len(report['findings'][0]['evidence']), 2)
        self.assertIn('db.execute(sql)', report['findings'][0]['evidence'][0]['quote'])
        self.assertEqual(report['coverage']['files_fully_read'], 2)
        self.assertEqual([e['tool'] for e in report['events']],
                         ['list_project_files', 'search_project', 'read_project_file', 'read_project_file', 'submit_report'])
        for request in ScriptedModel.requests:
            names = {t['function']['name'] for t in request['tools']}
            self.assertNotIn('task', names)
            self.assertNotIn('write_file', names)
            self.assertNotIn('execute', names)

    def test_graph_tools_in_real_harness(self):
        report = self.run_agent('graph', graphify=True)
        self.assertEqual(report['graph']['status'], 'ready')
        self.assertEqual([e['tool'] for e in report['events'][:3]],
                         ['graph_symbols', 'graph_neighbors', 'graph_path'])
        self.assertTrue(all(e['status'] == 'ok' for e in report['events'][:3]))
        self.assertEqual(len(report['findings']), 1)
        self.assertIn('graph_neighbors', {t['function']['name'] for t in ScriptedModel.requests[0]['tools']})

    def test_graph_tools_through_json_adapter(self):
        report = self.run_agent('graph', graphify=True, protocol='json')
        self.assertTrue(all(e['status'] == 'ok' for e in report['events'][:3]))
        self.assertEqual(report['report_source'], 'model')
        self.assertEqual(len(report['findings']), 1)
        self.assertIn('graph_neighbors', json.dumps(ScriptedModel.requests[0]['response_format']))

    def test_managed_queue_prevents_early_finish_and_covers_chunks(self):
        ScriptedModel.mode = 'early'
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            for source in (FIXTURES / 'vulnerable').glob('*.py'):
                (p / source.name).write_bytes(source.read_bytes())
            (p / 'aaa.py').write_text('x=1\n' * 310)
            scan_agent(p, 'scripted', LlamaCpp(self.http.server_port), self.update, lambda: False,
                       protocol='native', managed_traversal=True)
        self.assertEqual(self.report['coverage']['files_fully_read'], 3)
        chunks = [e for e in self.report['events'] if e['tool'] == 'assigned_source_chunk']
        self.assertEqual([e['args']['start_line'] for e in chunks[:3]], [1, 151, 301])
        self.assertTrue(any(e['tool'] == 'submit_report' and e['status'] == 'error' for e in self.report['events']))
        self.assertEqual(self.report['report_source'], 'model')
        self.assertIn('SERVER ASSIGNED SOURCE CHUNK', ScriptedModel.requests[0]['messages'][0]['content'])

    def test_graph_failure_keeps_source_review_available(self):
        with patch('sec_searcher.project_graph.build_project_graph', side_effect=RuntimeError('test indexing failure')):
            report = self.run_agent(graphify=True, managed_traversal=True)
        self.assertEqual(report['graph']['status'], 'error')
        self.assertEqual(report['coverage']['files_fully_read'], 2)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['report_source'], 'model')
        self.assertTrue(any('Graphify' in e['error'] for e in report['errors']))

    def test_managed_queue_budget_does_not_claim_unseen_files_read(self):
        report = self.run_agent('long', managed_traversal=True, max_steps=5)
        self.assertLess(report['coverage']['files_fully_read'], 37)
        self.assertTrue(report['coverage']['unread_files'])
        self.assertTrue(report['errors'])

    def test_safe_report(self):
        report = self.run_agent('safe')
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['coverage']['files_fully_read'], 2)

    def test_configured_budget_allows_more_than_thirty_turns(self):
        report = self.run_agent('long', max_steps=40)
        self.assertEqual(report['agent_steps'], 38)
        self.assertEqual(len(report['findings']), 1)
        self.assertIn('at most 40 model turns', ScriptedModel.requests[0]['messages'][0]['content'])

    def test_saved_findings_survive_empty_final_report(self):
        report = self.run_agent('saved_finish')
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['report_source'], 'model')
        self.assertEqual(report['errors'], [])
        self.assertIn('saved_findings', ScriptedModel.requests[-1]['messages'][0]['content'])
        self.assertIn('SQL injection', ScriptedModel.requests[-1]['messages'][0]['content'])

    def test_saved_findings_survive_model_failure(self):
        report = self.run_agent('saved_failure')
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['report_source'], 'service')
        self.assertTrue(report['summary'])
        self.assertTrue(report['errors'])

    def test_saved_findings_survive_cancellation(self):
        ScriptedModel.mode = 'saved_loop'
        scan_agent(FIXTURES / 'vulnerable', 'scripted', LlamaCpp(self.http.server_port),
                   self.update, lambda: bool(self.report['findings']), protocol='native')
        self.assertEqual(len(self.report['findings']), 1)
        self.assertEqual(self.report['report_source'], 'service')
        self.assertEqual(self.report['completion_reason'], 'Проверка остановлена пользователем')

    def test_repeated_reads_force_finalization_and_fallback(self):
        report = self.run_agent('saved_loop', max_steps=20)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['report_source'], 'service')
        self.assertTrue(any('Повторные' in e['error'] for e in report['errors']))
        names = {t['function']['name'] for t in ScriptedModel.requests[-1]['tools']}
        self.assertEqual(names, {'submit_report'})
        self.assertTrue(any(e['status'] == 'denied' for e in report['events']))
        self.assertLess(report['agent_steps'], 20)

    def test_final_step_requires_submission(self):
        report = self.run_agent('saved_auto_finish', max_steps=20, protocol='json')
        self.assertEqual(report['report_source'], 'model')
        self.assertEqual(report['events'][-1]['tool'], 'submit_report')
        self.assertEqual(len(report['findings']), 1)

    def test_finalize_saved_report_without_reanalysis(self):
        from scripts.finalize_report import finalize
        report = self.run_agent('saved_finish', protocol='json')
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'source.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                for p in (FIXTURES / 'vulnerable').glob('*.py'):
                    z.write(p, p.name)
            record = {'report': report, 'model': 'scripted', 'input_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
            ScriptedModel.mode = 'report_only'
            ScriptedModel.requests = []
            final = finalize(record, archive, LlamaCpp(self.http.server_port))
            self.assertEqual(final['report']['findings'], report['findings'])
            self.assertEqual(final['report']['report_source'], 'model')
            self.assertEqual(final['report']['finalization']['steps'], 1)
            self.assertEqual(len(ScriptedModel.requests), 1)
            record['input_sha256'] = 'wrong'
            with self.assertRaises(ValueError):
                finalize(record, archive, LlamaCpp(self.http.server_port))

    def test_invalid_step_budget(self):
        for value in (0, 501, True):
            with self.assertRaises(ValueError):
                self.run_agent(max_steps=value)

    def test_json_adapter_runs_real_harness(self):
        report = self.run_agent(protocol='json')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['coverage']['files_fully_read'], 2)
        self.assertGreaterEqual(len(ScriptedModel.requests), 5)
        for request in ScriptedModel.requests:
            self.assertIn('response_format', request)
            self.assertNotIn('tools', request)
            self.assertNotIn('maxLength', json.dumps(request['response_format']))

    def test_json_adapter_safe_report(self):
        report = self.run_agent('safe', protocol='json')
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['findings'], [])

    def test_hallucinated_evidence_is_rejected(self):
        report = self.run_agent('invalid_evidence', max_steps=6)
        self.assertEqual(report['findings'], [])
        self.assertTrue(report['errors'])
        self.assertEqual(report['agent_steps'], 6)

    def test_prose_is_not_success(self):
        report = self.run_agent('prose')
        self.assertTrue(report['errors'])
        self.assertEqual(report['coverage']['files_read'], 0)

    def test_retracted_invalid_finding_stays_unresolved(self):
        report = self.run_agent('retracted', protocol='json')
        self.assertEqual(report['findings'], [])
        self.assertTrue(any('отклонённых' in e['error'] for e in report['errors']))

    def test_denied_builtin_tools(self):
        report = self.run_agent('denied', max_steps=2)
        self.assertEqual(report['findings'], [])
        self.assertTrue(report['errors'])
        outputs = [m['content'] for r in ScriptedModel.requests for m in r['messages'] if m['role'] == 'tool']
        self.assertTrue(any('denied' in str(o).lower() for o in outputs))

    def test_cancel_before_first_model_request(self):
        scan_agent(FIXTURES / 'safe', 'scripted', LlamaCpp(self.http.server_port), self.update, lambda: True)
        self.assertEqual(ScriptedModel.requests, [])


class ProjectToolsTests(unittest.TestCase):
    def test_read_continuation_without_end_line(self):
        view = ProjectView([('a.py', '\n'.join('x=1' for _ in range(310)))], lambda **x: None)
        first = view.read('a.py')
        second = view.read('a.py', first['next_line'])
        self.assertEqual((second['start_line'], second['end_line']), (151, 300))
        self.assertEqual(view.progress()['next_unread'], [{'file': 'a.py', 'start_line': 301}])
        view.read('a.py', 301)
        self.assertEqual(view.progress()['next_unread'], [])

    def test_reads_are_bounded_and_cannot_escape(self):
        view = ProjectView([('src/a.py', '\n'.join('x=1' for _ in range(300)))], lambda **x: None)
        for path in ['/etc/passwd', '../src/a.py', 'src/../../a.py']:
            self.assertIn('error', view.read(path))
        result = view.read('src/a.py', 1, 1000000)
        self.assertEqual(result['end_line'], 150)
        self.assertEqual(view.coverage()['files_fully_read'], 0)
        self.assertEqual(view.search('x=1')['truncated'], True)


if __name__ == '__main__':
    unittest.main()
