# Docker

Команды выполняются из корня репозитория. Нужны Docker Engine / Docker Desktop и Compose v2. Основной сценарий — `docker compose build` и `docker compose up -d`.

## Состав

- `app`: Python 3.14, установленный пакет `sec_searcher` со статикой и зависимостями из `uv.lock`. Запуск от UID/GID 10001, корневая файловая система только для чтения, временный `/tmp` до 256 МиБ.
- `llama`: официальный CPU-образ `ghcr.io/ggml-org/llama.cpp:server`; `/models` подключён с хоста только для чтения. Для обновления образа выполните `docker compose pull llama`. Тег upstream обновляемый; для воспроизводимого развёртывания закрепите проверенный digest своего образа.
- Порт интерфейса опубликован только на `127.0.0.1:8765`. Порт модели наружу не публикуется; app обращается к `llama:8080` внутри сети Compose.

Источник: [официальные образы llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/docs/docker.md), [сеть Compose](https://docs.docker.com/compose/how-tos/networking/).

CPU-инференс модели 35B может быть существенно медленнее локального Metal. Compose не настраивает CUDA/Metal и не заменяет проверенный нативный запуск на Apple Silicon. Запуск двух экземпляров 35B одновременно требует дополнительной памяти; остановите нативную модель перед запуском полного Compose.

## Сборка только сервиса

```sh
docker build -t sec-searcher:local .
```

Образ не содержит моделей, тестов, бенчмарков, отчётов и локального `.venv`. Для подключения к уже работающей модели на Docker Desktop:

```sh
docker run --rm --init --read-only \
  --tmpfs /tmp:size=256m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8765:8765 \
  sec-searcher:local --llama-host host.docker.internal --agent-steps 100
```

Хост модели должен быть доступен из контейнера. На Linux потребуется `--add-host host.docker.internal:host-gateway`, а llama-server должен слушать доступный контейнеру интерфейс хоста. Не открывайте API модели в недоверенную сеть. Для полностью локального сценария без настройки маршрутизации используйте два контейнера Compose или нативный запуск из README.

`--llama-host` принимает имя хоста / IPv4, а не URL; порт задаётся отдельно через `--llama-port`. Это настройка администратора, она не поступает из загружаемого ZIP.

При изменении порта интерфейса меняйте одновременно порт приложения (`--port`), обе стороны `ports` и healthcheck. Проверка Host/Origin ожидает фактический порт сервера.

## Проверка и остановка

```sh
docker compose config --quiet
docker compose ps
docker compose logs --tail=100 app llama
curl --fail http://127.0.0.1:8765/api/models
docker compose down
```

Healthcheck app проверяет HTTP-сервис, а не готовность модели. Пока GGUF загружается, `/api/models` может отвечать 503; смотрите лог llama. Отсутствующий файл GGUF не скачивается автоматически.

Отчёты находятся в памяти приложения и теряются при остановке — предварительно экспортируйте JSON в интерфейсе. Исходники и данные проверяемых проектов не включаются в образ. Внешний сервер модели получает переданные агентом фрагменты: используйте только доверенный endpoint.

## Сборка с uv

Builder использует `uv sync --locked --no-dev --no-editable`. В runtime переносится готовое окружение с установленным пакетом: uv, исходный checkout, тесты и кэш сборки туда не копируются. Entry point — `sec-searcher`, сервер — FastAPI / Uvicorn с одним worker.

[Документация uv для Docker](https://docs.astral.sh/uv/guides/integration/docker/).

## Проверка миграции на src / FastAPI / uv

7 сентября 2026: `uv sync --locked`, `uv pip check` и Docker-сборка успешны. Все 44 теста прошли на macOS и в Linux-контейнере с установленным пакетом (включая Graphify, FastAPI, ограничения тела запроса и статику). Реальный запуск Uvicorn в контейнере проверен: HTTP 200, OpenAPI-схема, подключение к работающей Qwen и завершение lifespan по SIGTERM. Полный CPU-инференс 35B в Compose не повторялся.

## macOS Apple Silicon / Metal

```sh
bash install.sh --backend metal
```

`auto` выбирает Metal на Darwin/arm64. `compose.metal.yaml` содержит только FastAPI; модель запускается нативно через `scripts/metal.sh`. GPU определяется через `llama-server --list-devices`, все доступные слои выгружаются на GPU (`--n-gpu-layers 999`). Сервер модели слушает только `127.0.0.1:8080`, Docker Desktop обращается через `host.docker.internal`. Скрипт проверяет соединение из приложения и сообщает ошибку, если модель недоступна.

[Metal в llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md#metal-build), [сеть Docker Desktop](https://docs.docker.com/desktop/features/networking/).

Управление моделью: `bash scripts/metal.sh start|stop|status [MODEL_FILE]`. Лог — `.runtime/metal.log`, выбранная модель — `.runtime/metal.model` (не входят в Git/образ). Модель запускается как отдельная задача `launchd`, имя которой привязано к каталогу проекта. Повторный старт проверяет задачу и её готовность; остановка удаляет только эту задачу. Занятый другим сервером порт 8080 приводит к ошибке. После перезагрузки нужен повторный запуск. При ошибке запуска приложения уже загруженная модель остаётся доступной для диагностики; остановить её можно командой `stop`.

Перед переходом с CPU выполните `docker compose --env-file .env.install down`, чтобы не держать две модели в памяти. Для обратного перехода сначала остановите Metal. `docker compose down` сам по себе нативный процесс не останавливает.

Проверено на Apple M4 Pro: модель готова через `/health`, приложение `healthy`, генерация из контейнера завершилась ответом `OK.`. После завершения запуска процесс сохранился в launchd; повторный `start` использовал тот же процесс. Девять тестов установщика прошли. Тестовый короткий ответ не является оценкой качества аудита.
