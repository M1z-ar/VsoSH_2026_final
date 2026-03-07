import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass

from exceptions import InputError, TempError

try:
    import py7zr
except Exception:
    py7zr = None

try:
    import rarfile
except Exception:
    rarfile = None


@dataclass
class Extracted:
    root: str
    files: list[str]
    total_bytes: int


def _safe_join(root: str, name: str) -> str:
    root = os.path.abspath(root)
    target = os.path.abspath(os.path.join(root, name))
    if not (target == root or target.startswith(root + os.sep)):
        raise InputError("Архив содержит опасные пути")
    return target


def _walk(root: str) -> list[str]:
    out: list[str] = []
    for base, _, names in os.walk(root):
        for n in names:
            out.append(os.path.join(base, n))
    return out


def is_archive(name: str) -> bool:
    low = (name or "").lower()
    return low.endswith(".zip") or low.endswith(".7z") or low.endswith(".rar")


def extract_archive(
    body: bytes,
    file_name: str,
    *,
    max_files: int = 25,
    max_total_mb: int = 40,
    max_each_mb: int = 250,
) -> Extracted:
    tmp = tempfile.mkdtemp(prefix="scan_arc_")
    src = os.path.join(tmp, "src.bin")
    out_dir = os.path.join(tmp, "out")
    os.makedirs(out_dir, exist_ok=True)

    with open(src, "wb") as f:
        f.write(body)

    low = (file_name or "").lower()

    try:
        if low.endswith(".zip"):
            with zipfile.ZipFile(src) as z:
                for m in z.infolist():
                    if m.is_dir():
                        continue
                    dst = _safe_join(out_dir, m.filename)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    with z.open(m, "r") as fin, open(dst, "wb") as fout:
                        shutil.copyfileobj(fin, fout)

        elif low.endswith(".7z"):
            if py7zr is None:
                raise TempError("py7zr не установлен")
            with py7zr.SevenZipFile(src, mode="r") as z:
                z.extractall(path=out_dir)
            for p in _walk(out_dir):
                _safe_join(out_dir, os.path.relpath(p, out_dir))

        elif low.endswith(".rar"):
            if rarfile is None:
                raise TempError("rarfile не установлен")
            with rarfile.RarFile(src) as rf:
                for info in rf.infolist():
                    if info.isdir():
                        continue
                    dst = _safe_join(out_dir, info.filename)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    with rf.open(info) as fin, open(dst, "wb") as fout:
                        shutil.copyfileobj(fin, fout)
        else:
            raise InputError("Неизвестный формат архива")

        paths = _walk(out_dir)
        if not paths:
            raise InputError("Архив пустой")

        if len(paths) > max_files:
            raise InputError(f"Слишком много файлов в архиве (>{max_files})")

        max_total = max_total_mb * 1024 * 1024
        max_each = max_each_mb * 1024 * 1024

        total = 0
        clean: list[str] = []

        for p in paths:
            try:
                size = os.path.getsize(p)
            except OSError:
                continue

            if size <= 0:
                continue

            if size > max_each:
                raise InputError("В архиве есть слишком большой файл")

            total += size
            if total > max_total:
                raise InputError("Слишком большой общий размер распаковки")

            clean.append(p)

        if not clean:
            raise InputError("В архиве нет файлов для проверки")

        return Extracted(root=tmp, files=clean, total_bytes=total)

    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def cleanup(extracted: Extracted) -> None:
    shutil.rmtree(extracted.root, ignore_errors=True)
