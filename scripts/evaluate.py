"""Live ZIP → service → Deep Agents → llama.cpp smoke evaluation, never a mocked model."""
import argparse
import io
import json
import time
import urllib.request
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--model', default=None)
    parser.add_argument('--output', type=Path, default=Path('reports/live-evaluation.json'))
    parser.add_argument('--probe', action='store_true', help='Check native tool calling with a tiny request')
    parser.add_argument('--template', action='store_true', help='Inspect the rendered probe prompt')
    args = parser.parse_args()
    if args.probe or args.template:
        from sec_searcher.scanner import LlamaCpp
        client = LlamaCpp()
        model = args.model or client.models()[0]
        payload = {
            'model': model, 'messages': [{'role': 'user', 'content': 'List the project files using list_project_files. Call it once with empty arguments.'}],
            'tools': [{'type': 'function', 'function': {'name': 'list_project_files', 'description': 'List project files.', 'parameters': {'type': 'object', 'properties': {}}}}],
            'tool_choice': 'required', 'temperature': 0, 'max_tokens': 120, 'stream': False,
        }
        if args.template:
            print(json.dumps(client.request('/apply-template', payload), ensure_ascii=False, indent=2))
            return
        result = client.request('/v1/chat/completions', payload)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    base = f'http://127.0.0.1:{args.port}'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = ''

    def request(path, data=None):
        headers = {'X-CSRF-Token': token}
        if isinstance(data, dict):
            headers['Content-Type'] = 'application/json'
            data = json.dumps(data).encode()
        elif isinstance(data, bytes):
            headers['Content-Type'] = 'application/zip'
        req = urllib.request.Request(base + path, data=data, headers=headers)
        with opener.open(req, timeout=30) as response:
            return json.loads(response.read())

    token = request('/api/config')['token']
    available = request('/api/models')['models']
    model = args.model or available[0]
    results = {'model': model, 'note': 'Two synthetic fixtures; not a general security benchmark.', 'cases': []}
    for name in ('vulnerable', 'safe'):
        buffer = io.BytesIO()
        folder = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures' / name
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(folder.glob('*.py')):
                archive.writestr(path.name, path.read_bytes())
        upload = request('/api/upload', buffer.getvalue())
        request('/api/scan', {'project_id': upload['project_id'], 'model': model, 'mode': 'deep'})
        started = time.monotonic()
        previous = None
        while True:
            report = request('/api/scan')
            marker = (report['status'], report['agent_steps'], len(report['events']))
            if marker != previous:
                print(f"{name}: status={marker[0]}, turns={marker[1]}, actions={marker[2]}", flush=True)
                previous = marker
            if report['status'] != 'running':
                break
            if time.monotonic() - started > 1200:
                request('/api/cancel', {})
                raise TimeoutError('Live evaluation exceeded 20 minutes')
            time.sleep(1)
        common = report['status'] == 'done' and report['coverage']['files_fully_read'] == 2
        if name == 'vulnerable':
            passed = common and any(f['cwe'] == 'CWE-89' and len({e['file'] for e in f['evidence']}) >= 2 for f in report['findings'])
        else:
            passed = common and not report['findings']
        results['cases'].append({'fixture': name, 'passed': passed, 'seconds': round(time.monotonic() - started, 2), 'report': report})
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False))
        print(f'{name}: {"PASS" if passed else "FAIL"}', flush=True)
    raise SystemExit(0 if all(c['passed'] for c in results['cases']) else 1)


if __name__ == '__main__':
    main()
