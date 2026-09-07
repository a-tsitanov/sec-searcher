"""Isolated entry point: Graphify AST extraction only, never import uploaded code."""
import json
import sys
from pathlib import Path


def main():
    def deny_external(event, args):
        if event.startswith('socket.') or event in {'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'}:
            raise RuntimeError('Network and subprocesses are disabled in AST extraction')

    sys.addaudithook(deny_external)
    from graphify.extract import extract
    root = Path(sys.argv[1]).resolve()
    names = json.loads((root.parent / 'files.json').read_text())
    result = extract([root / n for n in names], root=root,
                     cache_root=root.parent / 'cache', parallel=False)
    data = json.dumps(result, ensure_ascii=False).encode()
    if len(data) > 32 * 1024 * 1024:
        raise ValueError('Graph exceeds 32 MiB')
    (root.parent / 'graph.json').write_bytes(data)


if __name__ == '__main__':
    main()
