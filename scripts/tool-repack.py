"""Maintainer-only exact-file subset of a pinned zstd tar, without filesystem extraction."""
import gzip
import json
import os
import subprocess
import sys
import tarfile

source, destination = sys.argv[1:3]
recipe = json.loads(sys.argv[3])
assert recipe['format'] == 'tar-zstd-subset-v1'
entries = recipe['entries']
assert 0 < len(entries) <= 100 and len(entries) == len(set(entries))
assert all(p and not p.startswith('/') and '\\' not in p and all(x not in ('', '.', '..') for x in p.split('/')) for p in entries)
assert recipe['stripPrefix'].endswith('/')
assert recipe['outputRoot'] and recipe['outputRoot'][0].isalnum() and all(c.isalnum() or c in '._-' for c in recipe['outputRoot'])
seen = set()
size = 0
process = subprocess.Popen(['zstd', '--long=30', '-dc', source], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
try:
    with tarfile.open(fileobj=process.stdout, mode='r|') as original, open(destination, 'xb') as output:
        with gzip.GzipFile(filename='', fileobj=output, mode='wb', compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                for member in original:
                    if not member.name.startswith(recipe['stripPrefix']):
                        continue
                    name = member.name[len(recipe['stripPrefix']):]
                    if name not in entries:
                        continue
                    assert name not in seen and member.isfile(), 'Selected entry is duplicate or not a regular file'
                    seen.add(name)
                    size += member.size
                    assert 0 <= member.size <= 256 * 1024**2 and size <= 512 * 1024**2
                    entry = tarfile.TarInfo(recipe['outputRoot'] + '/' + name)
                    entry.size = member.size
                    entry.mode = 0o755 if name.startswith('bin/') else 0o644
                    entry.mtime = 0
                    archive.addfile(entry, original.extractfile(member))
                extra_names = set()
                for alias in recipe.get('aliases', []):
                    name, target = alias['path'], alias['target']
                    assert name not in seen and name not in extra_names
                    assert name and not name.startswith('/') and '\\' not in name and all(x not in ('', '.', '..') for x in name.split('/'))
                    assert target and '/' not in target and '\\' not in target and target not in ('.', '..')
                    assert name.rsplit('/', 1)[0] + '/' + target in seen
                    extra_names.add(name)
                    entry = tarfile.TarInfo(recipe['outputRoot'] + '/' + name)
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = target
                    entry.mode = 0o777
                    archive.addfile(entry)
                for extra in recipe.get('appendFiles', []):
                    name = extra['path']
                    assert name and not name.startswith('/') and chr(92) not in name and all(x not in ('', '.', '..') for x in name.split('/'))
                    assert name not in seen and name not in extra_names
                    extra_names.add(name)
                    entry = tarfile.TarInfo(recipe['outputRoot'] + '/' + name)
                    entry.size = os.path.getsize(extra['file'])
                    assert entry.size <= 1024**2
                    entry.mode = 0o644
                    with open(extra['file'], 'rb') as notice:
                        archive.addfile(entry, notice)
    assert process.wait() == 0, 'Pinned zstd input failed to decode'
    assert seen == set(entries), 'Pinned archive omitted a selected entry'
finally:
    if process.poll() is None:
        process.kill()
        process.wait()
