"""Map schema-constrained local JSON actions to LangChain tool calls.

Some GGUF/template/server combinations emit prose instead of native tool_calls.
This adapter only implements the model protocol; Deep Agents still owns the loop.
"""
from __future__ import annotations

import json
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool


class LocalToolChat(BaseChatModel):
    model_name: str
    llama_client: Any
    max_tokens: int = 8192
    request_timeout: int = 360

    @property
    def _llm_type(self):
        return 'llama-cpp-json-tools'

    @property
    def _identifying_params(self):
        return {'model_name': self.model_name}

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self.bind(tools=[convert_to_openai_tool(t) for t in tools], **kwargs)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        tools = kwargs.get('tools') or []
        wire = []
        for message in messages:
            if message.type == 'tool':
                wire.append({'role': 'user', 'content': json.dumps({'tool_result': message.content}, ensure_ascii=False)})
            elif message.type == 'ai' and message.tool_calls:
                for call in message.tool_calls:
                    wire.append({'role': 'assistant', 'content': json.dumps({'name': call['name'], 'arguments': call['args']}, ensure_ascii=False)})
            else:
                role = {'human': 'user', 'ai': 'assistant', 'system': 'system'}.get(message.type, 'user')
                content = message.content if isinstance(message.content, str) else json.dumps(message.content, ensure_ascii=False)
                wire.append({'role': role, 'content': content})
        payload = {'model': self.model_name, 'messages': wire, 'temperature': 0,
                   'max_tokens': self.max_tokens, 'stream': False}
        if tools:
            choices = []
            descriptions = []
            for spec in tools:
                function = spec['function']
                choices.append({'type': 'object', 'properties': {
                    'name': {'type': 'string', 'enum': [function['name']]},
                    'arguments': function['parameters']}, 'required': ['name', 'arguments'], 'additionalProperties': False})
                descriptions.append(function)
            instructions = ('\n\nLOCAL TOOL PROTOCOL: Respond ONLY with one JSON object '
                            '{"name": "tool_name", "arguments": {...}}. Choose one available tool. '
                            'No XML, markdown, prose or simulated tool results. The service executes '
                            'your action and sends the real result. Finish using submit_report. Tools:\n' +
                            json.dumps(descriptions, ensure_ascii=False))
            if wire and wire[0]['role'] == 'system':
                wire[0]['content'] += instructions
            else:
                wire.insert(0, {'role': 'system', 'content': instructions})
            payload['response_format'] = {'type': 'json_object', 'schema': {'anyOf': choices}}
        result = self.llama_client.request('/v1/chat/completions', payload, timeout=self.request_timeout)
        choice = result['choices'][0]
        if choice['finish_reason'] != 'stop':
            phase = 'Выбор инструмента' if tools else 'Сжатие истории'
            raise ValueError(f'{phase}: ответ модели не завершён (finish_reason={choice["finish_reason"]}, max_tokens={self.max_tokens})')
        content = choice['message']['content']
        if tools:
            action = json.loads(content)
            if not isinstance(action, dict) or action.get('name') not in {t['function']['name'] for t in tools} or not isinstance(action.get('arguments'), dict):
                raise ValueError('Модель вернула некорректный выбор инструмента')
            # Deterministic per-turn ID; only one tool call is emitted per response.
            message = AIMessage(content='', tool_calls=[{'name': action['name'], 'args': action['arguments'],
                                                         'id': f'local_{len(messages)}', 'type': 'tool_call'}])
        else:
            message = AIMessage(content=content)
        usage = result.get('usage', {})
        if 'prompt_tokens' in usage and 'completion_tokens' in usage:
            message.usage_metadata = {'input_tokens': usage['prompt_tokens'], 'output_tokens': usage['completion_tokens'],
                                      'total_tokens': usage.get('total_tokens', usage['prompt_tokens'] + usage['completion_tokens'])}
        return ChatResult(generations=[ChatGeneration(message=message)])
