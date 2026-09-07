# HTTP API

Базовый адрес: `http://127.0.0.1:8765`. Один пользователь, один активный анализ.

| Метод | Путь | Тело / результат |
| --- | --- | --- |
| GET | `/api/config` | `token`, `max_upload_bytes` |
| GET | `/api/models` | `models`: список ID загруженных моделей; 503, если сервер недоступен |
| POST | `/api/upload` | ZIP в теле, `Content-Type: application/zip`; ответ 201 с `project_id`, `files` |
| POST | `/api/scan` | JSON `{"project_id":"…","model":"…","mode":"deep"}`; ответ 202 |
| GET | `/api/scan` | Текущий отчёт; `null` до первого запуска |
| POST | `/api/cancel` | JSON `{}`; запрос остановки |

Все POST требуют `X-CSRF-Token` из `/api/config`. JSON отправляется с `Content-Type: application/json`. Разрешены Host `127.0.0.1:<port>` / `localhost:<port>` и соответствующий HTTP Origin; сторонние значения отклоняются.

Режимы: `deep` (агент) и `files` (последовательный анализ). Остановка применяется после текущего запроса модели.

Статусы отчёта: `running`, `done`, `partial`, `cancelled`, `error`. Проверяйте `errors`, `skipped`, `limitations` и `coverage` вместе со статусом. Находки содержат путь, строку, критичность, CWE, объяснение и рекомендацию; агент добавляет проверенные цитаты. `verification: source_cited` означает подтверждение цитаты, а не доказательство эксплуатации.

API реализован на FastAPI. Схема доступна на `/openapi.json`; Swagger/ReDoc с внешними CDN отключены, чтобы интерфейс оставался автономным. Жизненный цикл временных данных привязан к [lifespan FastAPI](https://fastapi.tiangolo.com/advanced/events/).

Неверная структура JSON возвращает 422, превышение размера тела — 413, неподдерживаемый Content-Type — 415. Ошибки имеют поле `error`, совместимое с интерфейсом. Лимит проверяется и для потоковых запросов без Content-Length.
