"""Reorder the pinned standalone tar's chained links for safe extraction, preserving its exact logical tree."""
import copy,gzip,hashlib,json,pathlib,posixpath,sys,tarfile
source,output=sys.argv[1:3]
assert hashlib.sha256(pathlib.Path(source).read_bytes()).hexdigest()=='0a09ee3b82569e8985aff8186e4792618b8e5d0c766098db093d09a87d4b013a'
with tarfile.open(source) as original:
 entries=original.getmembers();assert len(entries)==327 and len({e.name for e in entries})==len(entries)
 for e in entries:
  assert e.name.startswith('mitmproxy.app') and not e.name.startswith('/') and '\\'not in e.name and '..'not in e.name.split('/') and not e.mode&0o7000
  assert e.isfile() or e.isdir() or e.issym()
  if e.issym():
   assert not e.linkname.startswith('/') and '\\'not in e.linkname
   target=posixpath.normpath(posixpath.join(posixpath.dirname(e.name),e.linkname));assert target.startswith('mitmproxy.app/')
 links={e.name:e for e in entries if e.issym()};dependencies={name:set() for name in links}
 for name,e in links.items():
  target=posixpath.normpath(posixpath.join(posixpath.dirname(name),e.linkname))
  # Alias must be written BEFORE a link appearing in any component of its target.
  dependencies[name]={other for other in links if target==other or target.startswith(other+'/')}
 assert all(name not in refs for name,refs in dependencies.items())
 pending=set(links);ordered=[]
 while pending:
  referenced=set().union(*(dependencies[n]&pending for n in pending));ready=sorted(pending-referenced);assert ready,'Cyclic symlink graph'
  for name in ready:ordered.append(links[name]);pending.remove(name)
 with open(output,'xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=9,mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as result:
  for entry in sorted((e for e in entries if not e.issym()),key=lambda e:e.name)+ordered:
   item=copy.copy(entry);item.uid=item.gid=0;item.uname=item.gname='';item.mtime=0;item.pax_headers={}
   result.addfile(item,original.extractfile(entry) if entry.isfile() else None)
