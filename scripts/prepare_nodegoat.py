"""Prepare a pinned NodeGoat source-only ZIP; never execute upstream code."""
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

from sec_searcher.archives import extract_project

REVISION = 'c5cb68a7084e4ae7dcc60e6a98768720a81841e8'
ROOT = Path('benchmarks/nodegoat')
STRIP_JS = r'''
const fs = require('fs');
const acorn = require('internal/deps/acorn/acorn/dist/acorn');
const source = fs.readFileSync(0, 'utf8');
const comments = [];
const options = {ecmaVersion:'latest', sourceType:'script'};
const before = acorn.parse(source, {...options, onComment:comments});
let clean = source;
for (const c of comments.reverse()) {
  clean = clean.slice(0,c.start) + clean.slice(c.start,c.end).replace(/[^\r\n]/g,' ') + clean.slice(c.end);
}
const after = acorn.parse(clean, options);
if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('AST changed');
process.stdout.write(clean);
'''


def main():
    archive = Path(sys.argv[1]).read_bytes()
    ROOT.mkdir(parents=True, exist_ok=True)
    upstream = ROOT / 'upstream'
    extract_project(archive, upstream)
    source = upstream / ('NodeGoat-' + REVISION)
    target = ROOT / 'input'
    target.mkdir(exist_ok=False)
    included, excluded = [], []
    for p in sorted(source.rglob('*')):
        if not p.is_file():
            continue
        name = p.relative_to(source).as_posix()
        keep = (name == 'server.js' or name == 'package.json' or
                name.startswith(('app/data/', 'app/routes/', 'config/')) or
                (name.startswith('app/views/') and not name.startswith('app/views/tutorial/')))
        if not keep or p.suffix not in {'.js', '.html', '.json'}:
            excluded.append(name)
            continue
        original = p.read_text()
        clean = original
        if p.suffix == '.js':
            clean = subprocess.run(['node', '--expose-internals', '-e', STRIP_JS],
                                   input=original, text=True, capture_output=True, check=True).stdout
        elif p.suffix == '.html':
            # Retain conditional browser comments, which can contain executable markup.
            clean = re.sub(r'<!--(?!\[if)[\s\S]*?-->|\{#[\s\S]*?#\}',
                           lambda m: re.sub(r'[^\r\n]', ' ', m[0]), clean)
        assert len(original.splitlines()) == len(clean.splitlines()), name
        out = target / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(clean)
        included.append({'file': name, 'bytes': out.stat().st_size,
                         'lines': len(clean.splitlines()),
                         'sha256': hashlib.sha256(out.read_bytes()).hexdigest()})
    zip_path = ROOT / 'nodegoat-source.zip'
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for item in included:
            z.write(target / item['file'], item['file'])
    manifest = {'repository': 'https://github.com/OWASP/NodeGoat', 'revision': REVISION,
                'upstream_zip_sha256': hashlib.sha256(archive).hexdigest(),
                'input_zip_sha256': hashlib.sha256(zip_path.read_bytes()).hexdigest(),
                'included': included, 'excluded': excluded,
                'preparation': 'Backend/config/templates/package manifest. JS comments blanked with Node bundled Acorn; full AST equality checked. HTML/Swig comments blanked except conditional comments. Line numbers retained. Tutorials/tests/assets/build/deploy files excluded.',
                'limitations': ['Known public training project; model familiarity cannot be ruled out.',
                                'Application branding and tutorial route names retained; not fully blinded.',
                                'Excluded assets and tutorial views remain referenced; this is a static review bundle, not a runnable distribution.']}
    (ROOT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'{zip_path}: {len(included)} files, {sum(x["lines"] for x in included)} lines, {sum(x["bytes"] for x in included)} bytes')


if __name__ == '__main__':
    main()
