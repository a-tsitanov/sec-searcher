import tempfile
import unittest
from pathlib import Path

from sec_searcher.agent_scan import ProjectView
from sec_searcher.project_graph import build_project_graph


class GraphTests(unittest.TestCase):
    def test_real_graph_cross_file_calls_without_execution_or_read_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / 'executed'
            files = [('a.py', 'from b import run\ndef entry(x):\n return run(x)\n'),
                     ('b.py', f'open({str(sentinel)!r}, "w").write("bad")\ndef run(x):\n return eval(x)\n'),
                     ('template.html', '<p>Not in a symbol graph</p>')]
            graph = build_project_graph(files)
            self.assertFalse(sentinel.exists())
        entry = graph.symbols('entry')['results'][0]['id']
        run = graph.symbols('run()')['results'][0]['id']
        path = graph.path(entry, run)['path']
        self.assertTrue(path)
        self.assertEqual(path[-1]['relation'], 'calls')
        self.assertEqual(path[-1]['source_file'], 'a.py')
        self.assertTrue(graph.neighbors(run, 'incoming')['results'])
        self.assertIn('template.html', graph.metadata['files_without_nodes'])
        view = ProjectView(files, lambda **x: None, graph=graph)
        self.assertEqual(view.coverage()['lines_read'], 0)
        self.assertIn('error', graph.neighbors('/etc/passwd'))
        self.assertIn('error', graph.path(entry, 'unknown'))

    def test_snapshot_path_escape_rejected(self):
        with self.assertRaises(ValueError):
            build_project_graph([('../escape.py', 'x=1')])

    def test_index_timeout_and_cancellation(self):
        with self.assertRaises(TimeoutError):
            build_project_graph([('a.py', 'x=1')], timeout=0)
        with self.assertRaisesRegex(RuntimeError, 'cancelled'):
            build_project_graph([('a.py', 'x=1')], cancelled=lambda: True)
