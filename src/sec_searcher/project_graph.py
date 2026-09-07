"""Bounded read-only queries over Graphify's local AST graph."""
from collections import Counter, deque
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time


class ProjectGraph:
    def __init__(self, raw, files):
        self.nodes = {}
        counts = Counter(n.get('id') for n in raw.get('nodes', []))
        for n in raw.get('nodes', []):
            path = n.get('source_file')
            location = re.fullmatch(r'L(\d+)(?:[-:]L?(\d+))?', n.get('source_location', ''))
            line = int(location[1]) if location else None
            if counts[n.get('id')] != 1 or path not in files or not line or not 1 <= line <= len(files[path].splitlines()):
                continue
            self.nodes[n['id']] = {'id': n['id'], 'label': n.get('label', '')[:200], 'file': path, 'line': line}
        self.edges = []
        self.adj = {n: [] for n in self.nodes}
        for e in raw.get('edges', []):
            if e.get('source') not in self.nodes or e.get('target') not in self.nodes:
                continue
            edge = {k: e.get(k) for k in ('source', 'target', 'relation', 'confidence', 'source_file', 'source_location')}
            if edge['source_file'] not in files:
                continue
            self.edges.append(edge)
            self.adj[edge['source']].append(edge)
            self.adj[edge['target']].append(edge)
        represented = {n['file'] for n in self.nodes.values()}
        self.metadata = {'engine': 'graphifyy', 'version': version('graphifyy'),
                         'nodes': len(self.nodes), 'edges': len(self.edges),
                         'files_with_nodes': len(represented),
                         'files_without_nodes': sorted(set(files) - represented),
                         'failed_sources': raw.get('failed_sources', []),
                         'duplicate_node_ids_dropped': sum(v > 1 for v in counts.values()),
                         'mode': 'local_ast_only', 'status': 'ready',
                         'limitations': 'Structural graph, not data-flow proof. Missing links do not prove absence of a call. Indexing does not count as model reading.'}

    @staticmethod
    def bounded(items):
        result = []
        size = 0
        for item in items:
            size += len(json.dumps(item, ensure_ascii=False))
            if len(result) >= 20 or size > 6000:
                return {'results': result, 'truncated': True}
            result.append(item)
        return {'results': result, 'truncated': False}

    def symbols(self, query):
        if not query or len(query) > 200:
            return {'error': 'Query must be 1–200 characters'}
        return self.bounded(n for n in self.nodes.values()
                            if query.casefold() in (n['label'] + ' ' + n['file']).casefold())

    def neighbors(self, symbol_id, direction='both'):
        if symbol_id not in self.nodes or direction not in {'both', 'incoming', 'outgoing'}:
            return {'error': 'Unknown symbol id or direction; use graph_symbols first'}
        items = []
        for e in self.adj[symbol_id]:
            outgoing = e['source'] == symbol_id
            if direction == 'incoming' and outgoing or direction == 'outgoing' and not outgoing:
                continue
            items.append({'edge': e, 'node': self.nodes[e['target'] if outgoing else e['source']]})
        return self.bounded(items)

    def path(self, source_id, target_id):
        if source_id not in self.nodes or target_id not in self.nodes:
            return {'error': 'Unknown symbol id; use graph_symbols first'}
        queue = deque([(source_id, [])])
        seen = {source_id}
        while queue and len(seen) <= 2000:
            current, path = queue.popleft()
            if current == target_id:
                return {'path': path, 'meaning': 'Directed structural links only; verify data flow in source.'}
            if len(path) >= 6:
                continue
            for edge in self.adj[current]:
                if edge['source'] != current or edge['relation'] in {'contains', 'method'}:
                    continue
                target = edge['target']
                if target not in seen:
                    seen.add(target)
                    queue.append((target, path + [edge]))
        return {'path': None, 'limitation': 'No path found within 6 hops / 2000 visited nodes; not proof of disconnection.'}


def build_project_graph(files, cancelled=lambda: False, timeout=60):
    started = time.monotonic()
    files = dict(files)
    with tempfile.TemporaryDirectory(prefix='sec-graphify-') as directory:
        base = Path(directory)
        root = base / 'source'
        root.mkdir()
        for name, content in files.items():
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name:
                raise ValueError('Invalid snapshot path')
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding='utf-8')
        (base / 'files.json').write_text(json.dumps(list(files)))
        # -I prevents imports from the uploaded project; no model/API credentials inherited.
        env = {k: os.environ[k] for k in ('PATH', 'LANG', 'TMPDIR', 'SYSTEMROOT') if k in os.environ}
        with (base / 'worker.log').open('wb') as log:
            process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).with_name('graphify_worker.py').resolve()), str(root)],
                                       cwd=base, env=env, stdout=log, stderr=log)
            try:
                while process.poll() is None:
                    if cancelled():
                        raise RuntimeError('Graph indexing cancelled')
                    if time.monotonic() - started > timeout:
                        raise TimeoutError('Graph indexing exceeded time limit')
                    time.sleep(.1)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
        if process.returncode:
            raise RuntimeError(f'Graphify AST worker failed (exit {process.returncode})')
        output = base / 'graph.json'
        if output.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('Graph exceeds 32 MiB')
        graph = ProjectGraph(json.loads(output.read_text()), files)
        graph.metadata.update(seconds=round(time.monotonic() - started, 3),
                              snapshot_sha256=hashlib.sha256(json.dumps(files, sort_keys=True, ensure_ascii=False).encode()).hexdigest())
        return graph
