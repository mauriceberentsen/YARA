#!/usr/bin/env python3

"""Create a deterministic archive for public schemas."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "yara.dev" / "v1alpha1"
OUTPUT_DIR = ROOT / "release-artifacts"
ARCHIVE_PATH = OUTPUT_DIR / "yara-schemas-v1alpha1.tar.gz"


def iter_schema_files() -> list[Path]:
    files = sorted(SCHEMA_DIR.glob("*.schema.json"))
    if not files:
        raise SystemExit(f"no schema files found in {SCHEMA_DIR}")
    return files


def add_file(archive: tarfile.TarFile, path: Path) -> None:
    data = path.read_bytes()
    rel_path = path.relative_to(ROOT).as_posix()
    info = tarfile.TarInfo(name=rel_path)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, fileobj=io.BytesIO(data))


def main() -> None:
    schema_files = iter_schema_files()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with ARCHIVE_PATH.open("wb") as raw_file:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_file,
            mtime=0,
        ) as gzip_file:
            with tarfile.open(fileobj=gzip_file, mode="w") as archive:
                for schema_file in schema_files:
                    add_file(archive, schema_file)
    print(f"created {ARCHIVE_PATH} with {len(schema_files)} schemas")


if __name__ == "__main__":
    main()
