"""FastAPI routes and request boundaries for the local single-user service."""
import asyncio
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from sec_searcher.archives import MAX_UPLOAD
from sec_searcher.scanner import LlamaCpp
from sec_searcher.service import State

WEB = Path(__file__).parent / 'web'


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    project_id: str = Field(min_length=1)
    model: str = Field(min_length=1, max_length=200)
    mode: Literal['deep', 'files'] | None = None


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')


async def read_body(request: Request, limit: int) -> bytes:
    """Bound actual streamed bytes, including requests without Content-Length."""
    declared = request.headers.get('content-length')
    if declared is not None:
        try:
            size = int(declared)
        except ValueError:
            raise HTTPException(400, 'Недопустимый размер запроса')
        if not 0 < size <= limit:
            raise HTTPException(413, 'Недопустимый размер запроса')
    body = bytearray()
    try:
        async with asyncio.timeout(15):
            async for chunk in request.stream():
                if len(body) + len(chunk) > limit:
                    raise HTTPException(413, 'Недопустимый размер запроса')
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, 'Истекло время загрузки')
    if not body or (declared is not None and len(body) != size):
        raise HTTPException(400, 'Тело запроса загружено не полностью')
    return bytes(body)


def create_app(state: State | None = None, *, port: int = 8765) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        app.state.scanner = state if state is not None else State(LlamaCpp())
        try:
            yield
        finally:
            await run_in_threadpool(app.state.scanner.close)

    app = FastAPI(title='Sec Searcher', version='0.1.0', lifespan=lifespan,
                  docs_url=None, redoc_url=None)
    hosts = {f'localhost:{port}', f'127.0.0.1:{port}'}

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse({'error': exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({'error': 'Недопустимые параметры запроса'}, status_code=422)

    @app.middleware('http')
    async def boundaries(request: Request, call_next):
        error = None
        if request.headers.get('host') not in hosts:
            error = 'Недопустимый Host'
        elif request.headers.get('origin') and request.headers['origin'] not in {f'http://{h}' for h in hosts}:
            error = 'Недопустимый Origin'
        elif request.method not in {'GET', 'HEAD', 'OPTIONS'} and not secrets.compare_digest(
                request.headers.get('x-csrf-token', '').encode(), request.app.state.scanner.token.encode()):
            error = 'Недопустимый токен'
        if error:
            response = JSONResponse({'error': error}, status_code=403)
        else:
            try:
                if request.method == 'POST':
                    content_type = 'application/zip' if request.url.path == '/api/upload' else 'application/json'
                    if request.headers.get('content-type', '').split(';')[0].strip() != content_type:
                        raise HTTPException(415, f'Требуется {content_type}')
                    request._body = await read_body(request, MAX_UPLOAD if request.url.path == '/api/upload' else 8192)
                response = await call_next(request)
            except HTTPException as exc:
                response = JSONResponse({'error': exc.detail}, status_code=exc.status_code)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @app.get('/api/config')
    def config(request: Request):
        return {'token': request.app.state.scanner.token, 'max_upload_bytes': MAX_UPLOAD}

    @app.get('/api/models')
    def models(request: Request):
        try:
            return {'models': request.app.state.scanner.client.models()}
        except Exception:
            raise HTTPException(503, 'llama-server недоступен. Запустите его с локальной GGUF-моделью.')

    @app.get('/api/scan')
    def report(request: Request):
        return request.app.state.scanner.snapshot()

    @app.post('/api/upload', status_code=201)
    async def upload(request: Request):
        try:
            return await run_in_threadpool(request.app.state.scanner.upload, await request.body())
        except (ValueError, OSError) as exc:
            raise HTTPException(400, str(exc))

    @app.post('/api/scan', status_code=202)
    def start(data: ScanRequest, request: Request):
        try:
            request.app.state.scanner.start(data.project_id, data.model, data.mode)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {'status': 'running'}

    @app.post('/api/cancel')
    def cancel(data: CancelRequest, request: Request):
        request.app.state.scanner.cancel.set()
        return {'status': 'cancellation_requested'}

    @app.get('/', include_in_schema=False)
    def index():
        return FileResponse(WEB / 'index.html')

    @app.get('/app.js', include_in_schema=False)
    def javascript():
        return FileResponse(WEB / 'app.js', media_type='text/javascript')

    @app.get('/style.css', include_in_schema=False)
    def stylesheet():
        return FileResponse(WEB / 'style.css', media_type='text/css')

    return app
