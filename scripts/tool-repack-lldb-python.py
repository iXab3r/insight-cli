"""Maintainer-only LLDB/Python closure from pinned Homebrew bottles and LLVM debugserver.

Usage: python3 tool-repack-lldb-python.py INPUT_DIRECTORY OUTPUT_TGZ LAYOUT_JSON
Only owned staging copies are relocated and signed. No Homebrew installation is required.
"""
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

inputs, destination, layout_file = map(pathlib.Path, sys.argv[1:4])
layout = json.loads(layout_file.read_text())
assert layout['schema'] == 1 and layout['format'] == 'lldb-python-closure-v1'
assert sys.platform == 'darwin' and os.uname().machine == 'arm64'

def verified(item):
    path = inputs / item['name']
    assert path.is_file() and path.stat().st_size == item['size']
    with path.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == item['sha256']
    return path

with tempfile.TemporaryDirectory(prefix='insight-lldb-repack-') as temporary:
    root = pathlib.Path(temporary).resolve() / layout['outputRoot']
    root.mkdir()
    cells = {item['id']: item['cell'] for item in layout['bottles']}
    for item in layout['bottles']:
        with tarfile.open(verified(item)) as archive:
            for member in archive:
                if member.isdir() and (member.name == item['cell'] or item['cell'].startswith(member.name + '/')):
                    continue
                assert member.name.startswith(item['cell'] + '/')
                relative = member.name[len(item['cell']) + 1:]
                selected = False
                if item['id'] == 'lldb':
                    selected = relative.startswith('lib/') or relative in ('bin/lldb', 'bin/lldb-argdumper', 'bin/darwin-debug')
                elif item['id'] == 'python@3.15':
                    selected = relative.startswith('Frameworks/Python.framework/') and '/test/' not in relative and '/idlelib/' not in relative and '/tkinter/' not in relative and '/Resources/Python.app/' not in relative
                    selected = selected and not re.search(r'/(readline|_tkinter)[.\-]', relative)
                else:
                    selected = relative.startswith('lib/') and '.dylib' in relative
                    if item['id'] == 'llvm':
                        selected = selected and pathlib.PurePosixPath(relative).name.startswith(('libLLVM', 'libclang-cpp', 'libc++', 'libunwind'))
                if selected:
                    if item['id'] == 'python@3.15' and relative.endswith('/site-packages') and member.issym():
                        (root / member.name).mkdir(parents=True, exist_ok=True)
                    else:
                        archive.extract(member, root, filter='data')
                if relative.startswith('.brew/') and member.isfile():
                    path = root / 'BUILD-RECIPES' / (item['id'].replace('@', '-') + '.rb')
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(archive.extractfile(member).read())

    def relocated(name):
        name = name.replace('@@HOMEBREW_PREFIX@@', '/opt/homebrew').replace('@@HOMEBREW_CELLAR@@', '/opt/homebrew/Cellar')
        if name.startswith('/opt/homebrew/opt/'):
            component, tail = name[len('/opt/homebrew/opt/'):].split('/', 1)
            return root / cells[component] / tail
        if name.startswith('/opt/homebrew/Cellar/'):
            return root / name[len('/opt/homebrew/Cellar/'):]
        return None

    native = []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open('rb') as stream:
            magic = stream.read(4).hex()
        if magic not in ('cffaedfe', 'cafebabe', 'feedfacf'):
            continue
        native.append(path)
        options = []
        for line in subprocess.check_output(['/usr/bin/otool', '-L', str(path)], text=True).splitlines()[1:]:
            name = line.strip().split(' (', 1)[0]
            target = relocated(name)
            if target:
                assert target.exists(), (str(path.relative_to(root)), name)
                options.extend(['-change', name, '@loader_path/' + os.path.relpath(target, path.parent)])
            elif name.startswith('/'):
                assert name.startswith(('/usr/lib/', '/System/Library/')), name
        if path.suffix == '.dylib' or path.name == 'Python':
            options.extend(['-id', '@rpath/' + path.name])
        if options:
            subprocess.run(['/usr/bin/install_name_tool', *options, str(path)], check=True, capture_output=True)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(path)], check=True, capture_output=True)

    binary = root / 'bin'
    binary.mkdir()
    (binary / 'lldb').symlink_to('../' + cells['lldb'] + '/bin/lldb')
    libraries = root / 'lib'
    libraries.mkdir()
    (libraries / 'liblldb.23.1.dylib').symlink_to('../' + cells['lldb'] + '/lib/liblldb.23.1.dylib')
    # Preserve the signed upstream helper bytes; it does not link our relocated libraries.
    with tarfile.open(verified(layout['debugserver'])) as archive:
        data = archive.extractfile(layout['debugserver']['path']).read()
        assert hashlib.sha256(data).hexdigest() == layout['debugserver']['binarySha256']
        (binary / 'debugserver').write_bytes(data)
        (binary / 'debugserver').chmod(0o755)

    notices = []
    for source in layout['sources']:
        with tarfile.open(verified(source)) as archive:
            for member in archive:
                if not member.isfile() or member.size > 2 * 1024**2 or not re.fullmatch(r'(LICENSE|COPYING|NOTICE|COPYRIGHT)([.\-][A-Za-z0-9_.\-]+)?', pathlib.PurePosixPath(member.name).name, re.I):
                    continue
                data = archive.extractfile(member).read()
                relative = pathlib.PurePosixPath('LICENSES') / source['id'] / member.name
                assert '..' not in relative.parts and not relative.is_absolute()
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                notices.append({'component': source['id'], 'sourcePath': member.name, 'path': str(relative), 'sha256': hashlib.sha256(data).hexdigest()})
    assert all(any(row['component'] == source['id'] for row in notices) for source in layout['sources'])
    for extra in layout.get('notices', []):
        path = root / 'LICENSES' / extra['name']
        path.write_bytes(verified(extra).read_bytes())
    (root / 'LICENSES/MANIFEST.json').write_text(json.dumps({'schema': 1, 'notices': notices}, indent=2, sort_keys=True) + '\n')
    (root / 'RUNTIME-MANIFEST.json').write_text(json.dumps(layout, indent=2, sort_keys=True) + '\n')
    for path in root.rglob('*'):
        if path.is_symlink():
            target = path.resolve(strict=True)
            assert target.is_relative_to(root), str(path.relative_to(root))
            # The strict Node extractor refuses traversing a link, including chained targets.
            # Keep every alias direct to its real owned file/directory instead of relaxing it.
            path.unlink()
            path.symlink_to(os.path.relpath(target, path.parent))
    with destination.open('xb') as output, gzip.GzipFile(filename='', fileobj=output, mode='wb', compresslevel=9, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(root.rglob('*')):
            member = archive.gettarinfo(str(path), arcname=layout['outputRoot'] + '/' + str(path.relative_to(root)))
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ''
            member.mode = 0o755 if path.is_dir() or path in native or path == binary / 'debugserver' else 0o777 if path.is_symlink() else 0o644
            if member.isfile():
                with path.open('rb') as stream:
                    archive.addfile(member, stream)
            else:
                archive.addfile(member)
print(json.dumps({'sha256': hashlib.file_digest(destination.open('rb'), 'sha256').hexdigest(), 'size': destination.stat().st_size, 'nativeFiles': len(native), 'notices': len(notices)}))
