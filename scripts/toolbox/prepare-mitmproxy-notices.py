"""Maintainer-only: flatten full, hash-bound notices collected from immutable original sources.
Input records have component, sourcePath, sha256 and a local file; private paths never ship.
"""
import hashlib,json,pathlib,re,sys
records=json.loads(pathlib.Path(sys.argv[1]).read_text());files={};manifest=[]
for record in records:
 data=pathlib.Path(record['file']).read_bytes();assert hashlib.sha256(data).hexdigest()==record['sha256'] and len(data)<1024**2
 name='notices/text/'+record['sha256']+'.txt';text=data.decode('utf-8',errors='strict');files[name]=text
 manifest.append({k:v for k,v in record.items() if k!='file'}|{'path':name})
files['notices/manifest.json']=json.dumps({'schema':1,'scope':'Complete source notices and upstream license declarations; locked Rust sources include other-platform/build-only packages, not a claim all are compiled into macOS. Standard SPDX texts are explicit references only, not invented copyright grants. Original corresponding sources are retained unchanged.','records':manifest},indent=2,sort_keys=True)+'\n'
pathlib.Path(sys.argv[2]).write_text(json.dumps(files,indent=2,ensure_ascii=True,sort_keys=True)+'\n')
