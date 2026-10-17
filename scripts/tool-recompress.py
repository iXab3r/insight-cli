"""Maintainer-only repack: preserve the original tar bytes, change xz to deterministic gzip."""
import gzip
import lzma
import shutil
import sys

with lzma.open(sys.argv[1], "rb") as source, open(sys.argv[2], "xb") as output:
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", compresslevel=9, mtime=0) as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)
