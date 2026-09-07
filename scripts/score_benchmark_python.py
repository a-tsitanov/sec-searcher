"""Score the selected CWE per BenchmarkPython case; incomplete cases remain unscored."""
import argparse
import json
from collections import Counter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=Path('reports/benchmark-python-qwen36.json'))
    parser.add_argument('--output', type=Path, default=Path('reports/benchmark-python-score.json'))
    args = parser.parse_args()
    manifest = json.loads(Path('benchmarks/benchmark-python/manifest.json').read_text())
    run = json.loads(args.report.read_text())
    report = run['report']
    coverage = report['coverage']
    incomplete = set(coverage['unread_files'] + coverage['partially_read_files'])
    has_report = any(e['tool'] == 'submit_report' and e['status'] == 'ok' for e in report['events'])
    cases, matched = [], set()
    for expected in manifest['expected']:
        hits = []
        for i, f in enumerate(report['findings']):
            paths = {e['file'] for e in f['evidence']}
            if f['cwe'] == expected['cwe'] and expected['file'] in paths:
                hits.append(i)
                matched.add(i)
        if not has_report or expected['file'] in incomplete:
            outcome = 'UNSCORED'
        elif expected['vulnerable']:
            outcome = 'TP' if hits else 'FN'
        else:
            outcome = 'FP' if hits else 'TN'
        cases.append({**expected, 'finding_indexes': hits, 'outcome': outcome})
    counts = Counter(c['outcome'] for c in cases)
    result = {'report_status': report['status'], 'seconds': run['seconds'],
              'counts': dict(counts), 'cases': cases,
              'other_findings': [{'index': i, 'finding': f} for i, f in enumerate(report['findings']) if i not in matched],
              'limitations': ['Exact CWE + cited file matching; descriptions must also be manually checked.',
                              'Only designated CWE scored; other findings are not automatically false positives.',
                              'Missing final report or unread target file is UNSCORED, never a true negative.',
                              'Selected eight cases only; not official OWASP Benchmark score.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(counts))


if __name__ == '__main__':
    main()
