"""Maintainer-only console subset of an already read-only mounted, hash-verified Wireshark DMG.
No Mach-O bytes are rewritten; framework aliases, native data and full notices are retained.
"""
import gzip,hashlib,io,json,pathlib,sys,tarfile
mounted,destination,encoded=sys.argv[1:4];recipe=json.loads(encoded);base=pathlib.Path(mounted).resolve();assert recipe['format']=='tshark-console-subset-v1';root=recipe['outputRoot'];assert root and all(c.isalnum() or c in '._-' for c in root)
entries=recipe['entries'];assert 0<len(entries)<=1000 and len({p['path'] for p in entries})==len(entries);seen=set();total=0
with open(destination,'xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=9,mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
 def add(name,data,mode=0o644):
  global total
  assert name and not name.startswith('/') and '\\'not in name and all(p not in ('','.','..') for p in name.split('/')) and name not in seen;seen.add(name);total+=len(data);assert total<512*1024**2
  entry=tarfile.TarInfo(root+'/'+name);entry.size=len(data);entry.mode=mode;entry.mtime=0;archive.addfile(entry,io.BytesIO(data))
 for item in entries:
  name=item['path'];path=base/name;assert path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(base);data=path.read_bytes();assert len(data)==item['size'] and hashlib.sha256(data).hexdigest()==item['sha256'];add(name,data,0o755 if name.endswith('/MacOS/tshark') else 0o644)
 for alias in recipe.get('aliases',[]):
  name,target=alias['path'],alias['target'];assert '/'not in target and '\\'not in target and target not in ('','.','..') and name not in seen and str(pathlib.PurePosixPath(name).parent/target) in seen
  entry=tarfile.TarInfo(root+'/'+name);entry.type=tarfile.SYMTYPE;entry.linkname=target;entry.mode=0o777;entry.mtime=0;archive.addfile(entry);seen.add(name)
 public=[]
 for index,item in enumerate(recipe['notices']):
  data=pathlib.Path(item['file']).read_bytes();assert hashlib.sha256(data).hexdigest()==item['sha256'] and len(data)<=2*1024**2
  name='LICENSES/'+item['component']+'/'+str(index)+'-'+pathlib.PurePosixPath(item['sourcePath']).name
  add(name,data);public.append({k:v for k,v in item.items() if k!='file'}|{'path':name})
 add('LICENSES/MANIFEST.json',(json.dumps({'schema':1,'notices':public},indent=2,sort_keys=True)+'\n').encode())
 add('RUNTIME-MANIFEST.json',(json.dumps({k:v for k,v in recipe.items() if k!='notices'}|{'noticeManifest':'LICENSES/MANIFEST.json'},indent=2,sort_keys=True)+'\n').encode())
