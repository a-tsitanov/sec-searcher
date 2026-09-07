import argparse
from sec_searcher.api import create_app
from sec_searcher.service import State
from sec_searcher.scanner import LlamaCpp


def main():
    parser = argparse.ArgumentParser(description='Локальный анализ исходного кода через llama.cpp')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--host', choices=('127.0.0.1', '0.0.0.0'), default='127.0.0.1',
                        help='Адрес сервиса; 0.0.0.0 только для контейнера с локальным опубликованным портом')
    parser.add_argument('--llama-host', default='127.0.0.1', help='Хост llama-server, например llama в Docker Compose')
    parser.add_argument('--llama-port', type=int, default=8080)
    parser.add_argument('--agent-steps', type=int, default=30, help='Лимит шагов Deep Agents (1–500)')
    parser.add_argument('--max-output-tokens', type=int, default=8192, help='Максимум токенов ответа модели (256–16384)')
    parser.add_argument('--agent-seconds', type=int, default=1800, help='Бюджет времени агента (60–7200 секунд)')
    parser.add_argument('--no-graphify', action='store_true', help='Отключить граф для сравнительного прогона')
    parser.add_argument('--no-managed-traversal', action='store_true', help='Оставить обход только на усмотрение модели')
    args = parser.parse_args()
    if not all(1 <= port <= 65535 for port in (args.port, args.llama_port)):
        parser.error('Порт должен быть от 1 до 65535')
    if not 1 <= args.agent_steps <= 500:
        parser.error('Лимит шагов агента должен быть от 1 до 500')
    if not 256 <= args.max_output_tokens <= 16384 or not 60 <= args.agent_seconds <= 7200:
        parser.error('Недопустимый лимит ответа или времени')
    state = State(LlamaCpp(args.llama_port, host=args.llama_host), agent_steps=args.agent_steps,
                  graphify=not args.no_graphify, managed_traversal=not args.no_managed_traversal,
                  max_output_tokens=args.max_output_tokens, agent_seconds=args.agent_seconds)
    import uvicorn
    uvicorn.run(create_app(state, port=args.port), host=args.host, port=args.port,
                proxy_headers=False, workers=1)


if __name__ == '__main__':
    main()
