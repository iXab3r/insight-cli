"""Maintainer-only console closure from a hash-checked DiE package; never run an installer."""
import gzip
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

source, destination = sys.argv[1:3]
r = json.loads(sys.argv[3])
assert r['format'] == 'die-pkg-console-v1'
root = r['outputRoot']
assert re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', root)
frameworks = ['QtConcurrent', 'QtCore', 'QtCore5Compat', 'QtNetwork', 'QtQml']
notices = {}
# Keep full license texts/attributions from all matching source companions, not an SPDX label.
for companion in r['sourceFiles']:
    label = companion['asset']
    assert '/' not in label and '\\' not in label
    with tarfile.open(companion['file'], 'r:*') as archive:
        for item in archive:
            parts = Path(item.name).parts
            if not parts or any(p in ('..', '.') for p in parts) or item.name.startswith('/'):
                raise ValueError('Unsafe source companion member')
            if item.isfile() and (any(p.lower() == 'licenses' for p in parts) or re.search(r'license|copying|copyright|notice|attribution', parts[-1], re.I)):
                assert item.size <= 4 * 1024**2
                notices['notices/' + label + '/' + item.name] = archive.extractfile(item).read()
assert any('LGPL-3.0' in p for p in notices) and any('GPL-3.0' in p for p in notices)
notices['NOTICE.txt'] = ('''Detect It Easy 3.21 console subset, unmodified executable/signature database and five dynamic Qt 6.11.0 frameworks.
Engine and component notices are under notices/. Qt is used under LGPL-3.0 (with its applicable exceptions and third-party terms).
The exact DiE source (including bundled submodules), Qt qtbase/qtdeclarative/qt5compat sources and their notices are companion assets in this same immutable GitHub release.
Qt frameworks remain dynamically linked and replaceable. To use modified compatible Qt libraries, copy this distribution to your own directory, replace its Frameworks, then select the copied MacOS/diec with insight-cli die install --executable. Managed installation integrity checks deliberately require reselection after modifications.
Reverse engineering for debugging such library modifications is permitted. No system framework or global installation is changed. This subset has no GUI, installer scripts or global trust changes.
''').encode()
with tempfile.TemporaryDirectory(prefix='insight-die-repack-') as temporary:
    expanded = Path(temporary) / 'expanded'
    subprocess.run(['/usr/sbin/pkgutil', '--expand-full', source, str(expanded)], check=True, capture_output=True, timeout=180)
    contents = expanded / 'Payload/Contents'
    selected = [contents / 'MacOS/diec', contents / 'Resources/qt.conf', contents / 'Resources/db', contents / 'Resources/db_custom']
    selected += [contents / ('Frameworks/' + name + '.framework') for name in frameworks]
    members = {}
    for start in selected:
        assert start.exists(), str(start)
        paths = [start] + (list(start.rglob('*')) if start.is_dir() else [])
        for path in paths:
            relative = path.relative_to(contents).as_posix()
            if '_CodeSignature' in path.parts:
                continue
            assert relative not in members
            if path.is_symlink():
                target = path.resolve(strict=True)
                assert target.is_relative_to(contents.resolve())
            members[relative] = path
    assert len(members) < 20000
    with open(destination, 'xb') as output, gzip.GzipFile(filename='', fileobj=output, mode='wb', compresslevel=9, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
            for name in sorted(members):
                path = members[name]
                entry = tarfile.TarInfo(root + '/' + name)
                entry.mtime = 0
                if path.is_symlink():
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = os.readlink(path)
                    entry.mode = 0o777
                    archive.addfile(entry)
                elif path.is_dir():
                    entry.type = tarfile.DIRTYPE
                    entry.mode = 0o755
                    archive.addfile(entry)
                else:
                    assert path.is_file()
                    entry.size = path.stat().st_size
                    assert entry.size <= 256 * 1024**2
                    entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    with path.open('rb') as data:
                        archive.addfile(entry, data)
            for name, data in sorted(notices.items()):
                entry = tarfile.TarInfo(root + '/' + name)
                entry.size = len(data)
                entry.mode = 0o644
                archive.addfile(entry, io.BytesIO(data))
