"""Scan lifecycle and temporary project storage, independent of HTTP."""
import json
import secrets
import threading
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from sec_searcher.scanner import scan
from sec_searcher.archives import extract_project

class State:
    def __init__(self, client, default_mode='deep', agent_steps=30, graphify=True, managed_traversal=True,
                 max_output_tokens=16384, agent_seconds=1800):
        if type(agent_steps) is not int or not 1 <= agent_steps <= 500:
            raise ValueError('Лимит шагов агента должен быть от 1 до 500')
        self.client = client
        self.default_mode = default_mode
        self.agent_steps = agent_steps
        self.graphify = graphify
        self.managed_traversal = managed_traversal
        if type(max_output_tokens) is not int or not 256 <= max_output_tokens <= 16384:
            raise ValueError('Лимит ответа должен быть от 256 до 16384 токенов')
        if type(agent_seconds) is not int or not 60 <= agent_seconds <= 7200:
            raise ValueError('Лимит времени должен быть от 60 до 7200 секунд')
        self.max_output_tokens = max_output_tokens
        self.agent_seconds = agent_seconds
        self.storage = tempfile.TemporaryDirectory(prefix="sec-searcher-")
        self.project = None
        self.project_id = None
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.report = None
        self.cancel = threading.Event()
        self.worker = None
        self.closing = False

    def upload(self, data):
        with self.lock:
            if self.closing:
                raise ValueError('Сервис останавливается')
            if self.report and self.report['status'] == 'running':
                raise ValueError('Дождитесь завершения текущей проверки')
            project_id = secrets.token_hex(16)
            project = Path(self.storage.name) / project_id
            count = extract_project(data, project)
            if self.project:
                shutil.rmtree(self.project)
            self.project, self.project_id = project, project_id
            return {'project_id': project_id, 'files': count}

    def start(self, project_id, model, mode=None):
        mode = mode or self.default_mode
        if mode not in {'deep', 'files'}:
            raise ValueError('Неизвестный режим проверки')
        if not isinstance(model, str) or not model or len(model) > 200:
            raise ValueError('Укажите модель')
        with self.lock:
            if self.closing:
                raise ValueError('Сервис останавливается')
            if self.report and self.report['status'] == 'running':
                raise ValueError('Проверка уже выполняется')
            if not self.project or project_id != self.project_id:
                raise ValueError('Сначала загрузите ZIP-архив')
            project = self.project
            self.cancel.clear()
            self.report = {'status': 'running', 'phase': 'Проверка модели', 'project_id': project_id, 'model': model,
                           'started_at': datetime.now(timezone.utc).isoformat(), 'total': 0, 'processed': 0,
                           'successful': 0, 'current_file': '', 'findings': [], 'errors': [], 'skipped': [],
                           'mode': mode, 'events': [], 'agent_steps': 0, 'agent_step_limit': self.agent_steps,
                           'coverage': None, 'summary': '', 'limitations': []}
            self.worker = threading.Thread(target=self.run, args=(project, model, mode), daemon=True)
            self.worker.start()

    def update(self, **values):
        with self.lock:
            for key, value in values.items():
                if key.startswith('add_'):
                    self.report[key[4:]].extend(value)
                elif key == 'successful_delta':
                    self.report['successful'] += value
                else:
                    self.report[key] = value

    def run(self, project, model, mode):
        try:
            self.client.ensure_local(model)
            self.update(phase='Чтение файлов')
            if mode == 'deep':
                from sec_searcher.agent_scan import scan_agent
                scan_agent(project, model, self.client, self.update, self.cancel.is_set,
                           max_steps=self.agent_steps, graphify=self.graphify, managed_traversal=self.managed_traversal,
                           max_output_tokens=self.max_output_tokens, max_seconds=self.agent_seconds)
            else:
                scan(project, model, self.client, self.update, self.cancel.is_set)
            with self.lock:
                self.report['current_file'] = ''
                self.report['finished_at'] = datetime.now(timezone.utc).isoformat()
                self.report['status'] = 'cancelled' if self.cancel.is_set() else ('partial' if self.report['errors'] else 'done')
        except Exception as exc:
            self.update(status='error', current_file='', finished_at=datetime.now(timezone.utc).isoformat(),
                        add_errors=[{'file': '', 'error': str(exc)[:500]}])

        finally:
            if self.closing:
                self.storage.cleanup()

    def close(self):
        with self.lock:
            self.closing = True
            self.cancel.set()
            worker = self.worker
        if worker is not None:
            worker.join(timeout=5)
        if worker is None or not worker.is_alive():
            self.storage.cleanup()

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.report))


