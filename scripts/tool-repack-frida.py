"""Maintainer-only Frida Node runtime assembly; runs no vendor installation code."""
import gzip, hashlib, io, json, sys, tarfile
native, output, encoded = sys.argv[1:4]
recipe = json.loads(encoded)
assert recipe['format'] == 'frida-node-runtime-v1'
assert len(recipe['sourceFiles']) == 1
root = recipe['outputRoot']
assert root and all(c.isalnum() or c in '._-' for c in root)
components = {'npm-frida': 'frida', 'npm-bindings': 'bindings', 'npm-file-uri-to-path': 'file-uri-to-path', 'npm-minimatch': 'minimatch', 'npm-brace-expansion': 'brace-expansion', 'npm-balanced-match': 'balanced-match'}
files, notices, index, seen = {}, {}, [], set()
def safe(name):
    assert name and not name.startswith('/') and '\\' not in name and all(p not in ('', '.', '..') for p in name.split('/'))
    return name
def retain(name, data):
    safe(name)
    assert name not in files and len(files) < 10000 and len(data) <= 256 * 1024**2
    files[name] = data
with tarfile.open(native, 'r:gz') as archive:
    entry = archive.getmember('build/frida_binding.node')
    assert entry.isfile()
    retain('node_modules/frida/build/frida_binding.node', archive.extractfile(entry).read())
with tarfile.open(recipe['sourceFiles'][0]['file'], 'r|gz') as sources:
    manifest = None
    for outer in sources:
        if outer.name.endswith('/SOURCE-MANIFEST.json'):
            manifest = json.load(sources.extractfile(outer))
            continue
        assert manifest is not None and outer.isfile()
        identifier = outer.name.rsplit('/', 1)[-1].removesuffix('.tar.gz')
        part = next(p for p in manifest['inputs'] if p['id'] == identifier)
        original = sources.extractfile(outer).read()
        assert len(original) == part['size'] and hashlib.sha256(original).hexdigest() == part['sha256']
        seen.add(identifier)
        with tarfile.open(fileobj=io.BytesIO(original), mode='r:gz') as archive:
            for member in archive:
                if not member.isfile():
                    continue
                if identifier in components:
                    assert member.name.startswith('package/')
                    local = safe(member.name.removeprefix('package/'))
                    if identifier != 'npm-frida' or local == 'package.json' or local.startswith('build/src/'):
                        retain('node_modules/' + components[identifier] + '/' + local, archive.extractfile(member).read())
                basename = member.name.rsplit('/', 1)[-1]
                if any(label in basename.upper() for label in ('LICENSE', 'COPYING', 'COPYRIGHT', 'NOTICE')) and member.size <= 1024**2:
                    data = archive.extractfile(member).read()
                    name = 'notices/' + identifier + '/' + hashlib.sha256(member.name.encode()).hexdigest()[:12] + '-' + basename[:80]
                    safe(name)
                    assert name not in notices
                    notices[name] = data
                    index.append({'path': name, 'source': identifier, 'original': member.name, 'sha256': hashlib.sha256(data).hexdigest()})
    assert manifest and seen == {p['id'] for p in manifest['inputs']}
assert all(identifier in seen for identifier in components)
metadata = json.loads(files['node_modules/frida/package.json'])
assert metadata['version'] == '17.24.0' and metadata['license'] == 'LGPL-2.0 WITH WxWindows-exception-3.1'
assert any(p['source'] == 'frida-core' and p['original'].endswith('/COPYING') for p in index)
assert any(p['source'] == 'glib' and p['original'].endswith('/COPYING') for p in index)
files.update(notices)
files['NOTICE-INDEX.json'] = (json.dumps(index, indent=2, sort_keys=True) + '\n').encode()
files['SOURCE-MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
files['NOTICE.txt'] = b'''Frida Node 17.24.0, official NAPI-v8 macOS ARM64 binding and unchanged runtime JavaScript dependencies.
Frida declares LGPL-2.0 WITH WxWindows-exception-3.1. Static native dependencies have their own terms.
Full retained upstream license/copyright/notice texts are under notices/, indexed with original source paths and SHA256 in NOTICE-INDEX.json.
Exact original source and component archives, including SDK dependencies and nested submodules, accompany this runtime in frida-17.24.0-sources.tgz. SOURCE-MANIFEST.json records bytes, revisions, origins and parent/submodule paths. Unpack those sources according to that manifest and follow the retained upstream build instructions to rebuild or modify the binding. A compatible rebuilt external bundle can be selected by the facade; it never deletes external files.
No npm install script or global Python/Frida installation is required. The consuming CLI uses its existing Node runtime.
'''
with open(output, 'xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=9, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
    for name, data in sorted(files.items()):
        entry = tarfile.TarInfo(root + '/' + safe(name))
        entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
        archive.addfile(entry, io.BytesIO(data))
