import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass

from errors import InputError, TempError

try:
    import py7zr
except Exception:
    py7zr = None

try:
    import rarfile
except Exception:
    rarfile = None


@dataclass
class Unpacked:
    root: str
    files: list[str]
    total_bytes: int


def walk_files(root: str) -> list[str]:
    files: list[str] = []
    for current, _, names in os.walk(root):
        for name in names:
            files.append(os.path.join(current, name))
    return files


def is_archive(file_name: str) -> bool:
    name = (file_name or "").lower()
    return name.endswith(".zip") or name.endswith(".7z") or name.endswith(".rar")


def extract_archive(
    file_bytes: bytes,
    file_name: str,
    *,
    max_files: int = 25,
    max_total_mb: int = 250,
    max_each_mb: int = 250,
) -> Unpacked:
    temp_dir = tempfile.mkdtemp(prefix="scan_")
    source_path = os.path.join(temp_dir, "archive.bin")
    out_dir = os.path.join(temp_dir, "files")
    os.makedirs(out_dir, exist_ok=True)

    with open(source_path, "wb") as f:
        f.write(file_bytes)

    name = (file_name or "").lower()

    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(source_path) as archive:
                archive.extractall(out_dir)
        elif name.endswith(".7z"):
            if py7zr is None:
                raise TempError("py7zr не установлен")
            with py7zr.SevenZipFile(source_path, mode="r") as archive:
                archive.extractall(path=out_dir)
        elif name.endswith(".rar"):
            if rarfile is None:
                raise TempError("rarfile не установлен")
            with rarfile.RarFile(source_path) as archive:
                archive.extractall(path=out_dir)
        else:
            raise InputError("Неизвестный формат архива")

        files = walk_files(out_dir)
        if not files:
            raise InputError("Архив пустой")

        if len(files) > max_files:
            raise InputError(f"Слишком много файлов в архиве: больше {max_files}")

        max_total = max_total_mb * 1024 * 1024
        max_each = max_each_mb * 1024 * 1024
        total = 0
        checked_files: list[str] = []

        for path in files:
            size = os.path.getsize(path)
            if size <= 0:
                continue
            if size > max_each:
                raise InputError("В архиве есть слишком большой файл")

            total += size
            if total > max_total:
                raise InputError("Слишком большой общий размер после распаковки")

            checked_files.append(path)

        if not checked_files:
            raise InputError("В архиве нет файлов для проверки")

        return Unpacked(root=temp_dir, files=checked_files, total_bytes=total)

    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def cleanup(unpacked: Unpacked) -> None:
    shutil.rmtree(unpacked.root, ignore_errors=True)
