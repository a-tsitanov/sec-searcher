"""Prepare a deterministic 8-case OWASP BenchmarkPython subset, keeping labels separate."""
import ast
import csv
import hashlib
import io
import json
import sys
import tokenize
import zipfile
from pathlib import Path

from sec_searcher.archives import extract_project

REVISION = 'f1291485808b66e20ddb6b01b10dc71b3df8c8ba'
ROOT = Path('benchmarks/benchmark-python')


def clean_python(source):
    lines = source.splitlines(keepends=True)
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            row, start = token.start
            _, end = token.end
            lines[row - 1] = lines[row - 1][:start] + ' ' * (end - start) + lines[row - 1][end:]
    clean = ''.join(lines)
    assert ast.dump(ast.parse(source)) == ast.dump(ast.parse(clean))
    assert len(source.splitlines()) == len(clean.splitlines())
    return clean


def main():
    archive = Path(sys.argv[1]).read_bytes()
    ROOT.mkdir(parents=True, exist_ok=True)
    extract_project(archive, ROOT / 'upstream')
    source = ROOT / 'upstream' / ('BenchmarkPython-' + REVISION)
    rows = list(csv.reader((source / 'expectedresults-0.1.csv').read_text().splitlines()))[1:]
    selected = []
    for category in ['sqli', 'cmdi', 'pathtraver', 'deserialization']:
        for expected in ['true', 'false']:
            row = next(r for r in rows if r[1] == category and r[2] == expected)
            selected.append({'id': row[0], 'category': category, 'vulnerable': expected == 'true',
                             'cwe': 'CWE-' + row[3], 'file': 'testcode/' + row[0] + '.py'})
    paths = [source / x['file'] for x in selected]
    paths += sorted((source / 'helpers').rglob('*'))
    paths += [source / 'app.py', source / 'requirements.txt']
    included = []
    target = ROOT / 'input'
    target.mkdir(exist_ok=False)
    for p in paths:
        if not p.is_file():
            continue
        name = p.relative_to(source).as_posix()
        data = p.read_bytes()
        if p.suffix == '.py':
            data = clean_python(data.decode()).encode()
        out = target / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        included.append({'file': name, 'sha256': hashlib.sha256(data).hexdigest()})
    with zipfile.ZipFile(ROOT / 'benchmark-python-source.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        for item in included:
            z.write(target / item['file'], item['file'])
    manifest = {'repository': 'https://github.com/OWASP-Benchmark/BenchmarkPython', 'revision': REVISION,
                'selection': 'First true and first false row in upstream CSV for sqli/cmdi/pathtraver/deserialization; selected before inference.',
                'expected': selected, 'included': included,
                'upstream_zip_sha256': hashlib.sha256(archive).hexdigest(),
                'input_zip_sha256': hashlib.sha256((ROOT / 'benchmark-python-source.zip').read_bytes()).hexdigest(),
                'limitations': ['8-case convenience subset; not official Benchmark scoring.',
                                'Labels apply only to each designated CWE, not every possible issue in the file or shared helpers.',
                                'Comments removed with AST equality checked; license docstrings and category-bearing routes retained. Not fully blinded.',
                                'Shared helpers included; templates/test database fixtures omitted. Static review only.']}
    (ROOT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(selected, indent=2))


if __name__ == '__main__':
    main()
