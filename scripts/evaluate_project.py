"""Run an existing ZIP through the local service and persist all progress/results."""
import argparse
import hashlib
import json
import time
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('zip', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--model', default='sec-qwen36-unsloth')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--timeout', type=int, default=2400, help='Общий таймаут прогона в секундах')
    args = parser.parse_args()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = ''

    def request(path, data=None):
        headers = {'X-CSRF-Token': token}
        if isinstance(data, dict):
            headers['Content-Type'] = 'application/json'
            data = json.dumps(data).encode()
        elif isinstance(data, bytes):
            headers['Content-Type'] = 'application/zip'
        req = urllib.request.Request(f'http://127.0.0.1:{args.port}' + path, data=data, headers=headers)
        with opener.open(req, timeout=30) as response:
            return json.loads(response.read())

    token = request('/api/config')['token']
    active = request('/api/scan')
    if active and active['status'] == 'running':
        raise RuntimeError('Another scan is already running')
    if args.model not in request('/api/models')['models']:
        raise ValueError('Requested model is not loaded')
    data = args.zip.read_bytes()
    uploaded = request('/api/upload', data)
    request('/api/scan', {'project_id': uploaded['project_id'], 'model': args.model, 'mode': 'deep'})
    started = time.monotonic()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    while True:
        report = request('/api/scan')
        if report['project_id'] != uploaded['project_id']:
            raise RuntimeError('Scan was replaced by another request')
        result = {'model': args.model, 'input_zip': str(args.zip),
                  'input_sha256': hashlib.sha256(data).hexdigest(),
                  'seconds': round(time.monotonic() - started, 2), 'report': report}
        temporary = args.output.with_suffix('.tmp')
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        temporary.replace(args.output)
        marker = (report['status'], report['agent_steps'], len(report['events']))
        if marker != previous:
            print(f'status={marker[0]} turns={marker[1]} actions={marker[2]} findings={len(report["findings"])}', flush=True)
            previous = marker
        if report['status'] != 'running':
            break
        if time.monotonic() - started > args.timeout:
            request('/api/cancel', {})
            raise TimeoutError(f'Evaluation exceeded {args.timeout} seconds; last progress saved')
        time.sleep(1)
    # Completion is not a correctness score. Assess findings separately against a reference.
    raise SystemExit(0 if report['status'] == 'done' else 1)


if __name__ == '__main__':
    main()
