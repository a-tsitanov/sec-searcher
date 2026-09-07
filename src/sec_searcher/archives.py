"""Bounded ZIP extraction into a fresh, service-owned directory."""
import io
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_UPLOAD = 25 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
MAX_ENTRIES = 5000


def extract_project(data: bytes, destination: Path):
    if destination.exists():
        raise ValueError('Для распаковки требуется новый каталог')
    if len(data) > MAX_UPLOAD:
        raise ValueError('ZIP больше 25 МиБ')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise ValueError('В архиве больше 5000 записей')
            if sum(item.file_size for item in entries) > MAX_UNPACKED:
                raise ValueError('Распакованный проект больше 32 МиБ')
            targets = set()
            planned = []
            for item in entries:
                name = item.orig_filename
                parts = PurePosixPath(name).parts
                if not parts or '\x00' in name or '\\' in name or ':' in name or name.startswith('/') or '..' in parts:
                    raise ValueError('Архив содержит небезопасный путь')
                mode = item.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError('Ссылки и специальные файлы в ZIP не поддерживаются')
                if item.flag_bits & 1:
                    raise ValueError('Зашифрованные ZIP не поддерживаются')
                if len(name) > 1000 or len(parts) > 40:
                    raise ValueError('Слишком длинный или глубокий путь в архиве')
                target = destination.joinpath(*parts)
                # Conservative case-insensitive collision check for macOS/Windows.
                key = '/'.join(parts).casefold()
                if key in targets:
                    raise ValueError('Повторяющиеся пути в архиве')
                targets.add(key)
                planned.append((item, target))
            destination.mkdir(parents=True, exist_ok=False)
            total, count = 0, 0
            for item, target in planned:
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as source, target.open('xb') as output:
                    while block := source.read(65536):
                        total += len(block)
                        if total > MAX_UNPACKED:
                            raise ValueError('Распакованный проект больше 32 МиБ')
                        output.write(block)
                count += 1
            if not count:
                raise ValueError('В архиве нет файлов')
            return count
    except Exception as exc:
        if destination.exists():
            shutil.rmtree(destination)
        if isinstance(exc, ValueError):
            raise
        raise ValueError('Не удалось распаковать ZIP: повреждённый архив или конфликт путей') from exc
