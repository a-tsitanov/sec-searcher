# Утилиты разработки

Запускайте **из корня репозитория** через `uv run python -m scripts.<имя>`. Эти команды не входят в Docker-образ сервиса.

| Модуль | Назначение |
| --- | --- |
| `evaluate` | Живой тест модели на двух маленьких уязвимом/безопасном проектах; нужны сервис и llama-server |
| `evaluate_project` | Загрузить подготовленный ZIP в сервис, дождаться отчёта и сохранить JSON |
| `finalize_report` | Получить финальную сводку LLM для уже прочитанного отчёта с проверкой исходного ZIP |
| `prepare_nodegoat` | Подготовить фиксированную версию NodeGoat |
| `prepare_benchmark_python` | Подготовить фиксированный набор BenchmarkPython |
| `score_benchmark_python` | Сопоставить результат с ожидаемыми метками тестов |

Для CLI-утилит смотрите `--help`. Подготовка бенчмарков работает с фиксированными путями; точные предварительные шаги и требования приведены в [методике](../docs/BENCHMARKS.md). Наборы нельзя считать слепым тестом: проекты публичны.

```sh
uv run python -m scripts.evaluate
uv run python -m scripts.evaluate_project --help
uv run python -m scripts.finalize_report --help
```

Восстановление финальной сводки не выполняет новый аудит и не устраняет ошибки исследования. Сохраняйте оригинальный отчёт вместе с результатом финализации.

`metal.sh` — управление нативным llama.cpp на macOS Apple Silicon: `bash scripts/metal.sh start|stop|status [MODEL_FILE]`. Вызывается установщиком в режиме Metal.
