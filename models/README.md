# Модели

Текущая модель: **Unsloth Qwen3.6-35B-A3B UD-Q3_K_M**.

- GGUF: `Qwen3.6-35B-A3B-UD-Q3_K_M.gguf` (16 600 710 112 байт).
- [Репозиторий Hugging Face](https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF).
- Ревизия: `a483e9e6cbd595906af30beda3187c2663a1118c`.
- SHA256: `1b715841683f960bd9a49f008181bd910ee169b78d4cf465b6fde7f4d929ff99`.
- Команда запуска: [основной README](../README.md).

Веса исключены из Git и Docker-контекста. Сервис и Compose не скачивают их автоматически. Метаданные, шаблоны и манифесты ниже сохранены для воспроизводимости прежних экспериментов; старые команды не являются текущей настройкой по умолчанию.

## История моделей

### Qwen2.5-Coder — архивный эксперимент

- Репозиторий: https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF
- Файл: `qwen2.5-coder-7b-instruct-q5_k_m.gguf`
- SHA256: `586844eac4d6d6321689f0192c8aa8e69cd8625974a5cc2d925b1a03366e4d16`
- Источник контрольной суммы: https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/blob/main/qwen2.5-coder-7b-instruct-q5_k_m.gguf
- Лицензия модели: Apache-2.0, см. исходный репозиторий.
- GGUF исключён из Git. Модель загружается один раз, инференс локальный.

```sh
llama-server -m models/qwen2.5-coder-7b-instruct-q5_k_m.gguf --alias sec-qwen-coder --host 127.0.0.1 --port 8080 -c 16384 -np 1 --jinja --chat-template-file models/qwen-tools.jinja
```

Шаблон `qwen-tools.jinja` извлечён из официального `tokenizer_config.json`: https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct/blob/main/tokenizer_config.json . Сохранён для воспроизводимости диагностики. Нативный tool calling не прошёл проверку ни со встроенным шаблоном, ни с этим; рабочая интеграция использует JSON-адаптер. См. `VALIDATION.md`.


## VulnLLM-R-7B — следующая модель для сравнения

- Исходная модель: https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B
- GGUF сообщества: https://huggingface.co/mradermacher/VulnLLM-R-7B-GGUF
- Ревизия GGUF: `6ce5015efa4210be17c1c3034ba5dd5ca36d0d63`
- Файл: `VulnLLM-R-7B.Q5_K_M.gguf`, 5 444 832 160 байт.
- Проверенный SHA256: `987452d4b09ead07c488f500ee1f8970e6ce47b76a1d7dd72991c76caccfa8cb`
- Параметры сравнения и хеши фикстур: `vulnllm-run-manifest.json`.

Загрузка завершена, SHA256 совпала с метаданными Hugging Face. Запуск:

```sh
llama-server -m models/VulnLLM-R-7B.Q5_K_M.gguf --alias sec-vulnllm-r --host 127.0.0.1 --port 8080 -c 16384 -np 1 --jinja
```

Веб-сервис использует тот же адрес модели. Сравнительный прогон:

```sh
.venv/bin/python -m scripts.evaluate --model sec-vulnllm-r --output reports/vulnllm-evaluation.json
```


## Qwen3.6-35B-A3B — Unsloth

- Источник: https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF
- Ревизия: `a483e9e6cbd595906af30beda3187c2663a1118c`.
- Файл: `Qwen3.6-35B-A3B-UD-Q3_K_M.gguf`, 16 600 710 112 байт.
- Проверенный SHA256: `1b715841683f960bd9a49f008181bd910ee169b78d4cf465b6fde7f4d929ff99`.
- Метаданные и параметры прогона: `qwen36-unsloth-run-manifest.json`.
- Старые веса Qwen2.5-Coder удалены с разрешения пользователя для освобождения диска; отчёты и сведения об источнике сохранены. VulnLLM остаётся на диске.

```sh
llama-server -m models/Qwen3.6-35B-A3B-UD-Q3_K_M.gguf --alias sec-qwen36-unsloth --host 127.0.0.1 --port 8080 -c 16384 -np 1 --jinja --reasoning off --cache-ram 0
.venv/bin/python -m scripts.evaluate --model sec-qwen36-unsloth --output reports/qwen36-unsloth-evaluation.json
```

Фактический прогон дополнительно содержал `--chat-template-kwargs '{"enable_thinking":false}'`. В llama.cpp b9290 это избыточный устаревший параметр; лог подтверждает `thinking = 0`. Команда выше использует рекомендуемый сервером `--reasoning off`. Дополнительный RAM-кэш промптов отключён ради памяти, кэш текущего слота остаётся внутренним механизмом llama.cpp.
