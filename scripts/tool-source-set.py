"""Maintainer-only deterministic retention of exact upstream source/component archives."""
import gzip, hashlib, io, json, os, sys, tarfile
output, encoded = sys.argv[1:3]
recipe = json.loads(encoded)
assert recipe['format'] == 'source-set-v1'
parts = recipe['inputs']
assert 0 < len(parts) <= 100 and len({p['id'] for p in parts}) == len(parts)
root = recipe['outputRoot']
assert root and all(c.isalnum() or c in '._-' for c in root)
public = [{k: v for k, v in p.items() if k != 'file'} for p in parts]
with open(output, 'xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=9, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
    def add(name, stream, size):
        entry = tarfile.TarInfo(root + '/' + name)
        entry.size, entry.mode, entry.mtime = size, 0o644, 0
        archive.addfile(entry, stream)
    manifest = (json.dumps({'schema': 1, 'inputs': public}, indent=2, sort_keys=True) + '\n').encode()
    add('SOURCE-MANIFEST.json', io.BytesIO(manifest), len(manifest))
    total = 0
    for part in parts:
        assert part['id'] and all(c.isalnum() or c in '._-' for c in part['id'])
        assert os.path.getsize(part['file']) == part['size']
        with open(part['file'], 'rb') as source:
            assert hashlib.file_digest(source, 'sha256').hexdigest() == part['sha256']
            total += part['size']
            assert total < 2 * 1024**3
            source.seek(0)
            add('inputs/' + part['id'] + '.tar.gz', source, part['size'])
