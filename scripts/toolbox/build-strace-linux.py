#!/usr/bin/env python3
"""Maintainer-only exact-source build, reproducibility and owned Linux ptrace proof."""
import hashlib,json,os,pathlib,platform,shutil,subprocess,sys,tarfile,tempfile,urllib.request,gzip,time,signal
assert sys.platform=='linux' and platform.machine()=='x86_64'
assert os.environ.get('INSIGHT_NATIVE_DISPOSABLE')=='1'
repository=pathlib.Path(__file__).resolve().parents[2];output=pathlib.Path(sys.argv[1]).resolve();output.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
source=output/'strace-7.2.tar.xz'
if not source.exists():source.write_bytes(urllib.request.urlopen('https://github.com/strace/strace/releases/download/v7.2/strace-7.2.tar.xz').read())
assert sha(source)=='4bde6246926890dcee824f6e6ac42a06752f47d77e5097d86e3c0d6d4b709fe5'
env={**os.environ,'SOURCE_DATE_EPOCH':'0','LC_ALL':'C','TZ':'UTC'}
def run(args,**kwargs):return subprocess.check_output(args,env=env,stderr=subprocess.STDOUT,**kwargs)
with tempfile.TemporaryDirectory(prefix='insight-strace-build-') as temporary:
 root=pathlib.Path(temporary);binaries=[];directories=[]
 for label in ['first','second']:
  location=root/label;location.mkdir()
  with tarfile.open(source) as archive:archive.extractall(location,filter='data')
  directory=location/'strace-7.2';directories.append(directory)
  flags='-O2 -g0 -ffile-prefix-map='+str(directory)+'=/_/strace'
  subprocess.run(['./configure','--enable-mpers=no','--with-libdw=no','--with-libunwind=no'],cwd=directory,env={**env,'CFLAGS':flags},stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT,check=True)
  subprocess.run(['make','-j2'],cwd=directory,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT,check=True)
  binary=directory/'src/strace';subprocess.run(['strip','--strip-unneeded',str(binary)],check=True);binaries.append(binary)
 assert sha(binaries[0])==sha(binaries[1]),'Independent source build binaries differ'
 package=root/'strace-7.2';(package/'bin').mkdir(parents=True)
 shutil.copyfile(binaries[0],package/'bin/strace');(package/'bin/strace').chmod(0o755)
 run(['cc','-O2','-g0','-Wl,--build-id=sha1',str(repository/'skills/ghidra-coordinator/runtime/native/deadline-exec.c'),'-o',str(package/'bin/deadline-exec')])
 for name in ['COPYING','LGPL-2.1-or-later']:
  shutil.copyfile(directories[0]/name,package/name)
 dependency=run(['ldd',str(package/'bin/strace')]).decode()
 assert all(any(term in line for term in ['linux-vdso','libc.so.6','ld-linux-x86-64']) for line in dependency.splitlines()),dependency
 # Actual owned input observation, followed by kill-on-exit of an owned native descendant.
 fixture=root/'probe.c';fixture.write_text('#include <unistd.h>\n#include <stdio.h>\n#include <fcntl.h>\n#include <stdlib.h>\nint main(int n,char**v){int f=open(v[1],O_RDONLY);char b[64]={0};read(f,b,63);puts(b);close(f);if(n>2){pid_t c=fork();if(!c){for(;;)pause();}FILE*p=fopen(v[2],"w");fprintf(p,"%d %d",getpid(),c);fclose(p);for(;;)pause();}return 0;}\n')
 executable=root/'probe';run(['cc','-O0',str(fixture),'-o',str(executable)])
 data=root/'owned-settings.txt';data.write_text('owned-report Pending37')
 trace=run([str(binaries[0]),'--kill-on-exit','-f','-s','128','-yy','-e','trace=openat,read,write',str(executable),str(data)]).decode()
 assert 'owned-report Pending37' in trace and 'owned-settings.txt' in trace
 marker=root/'pids';process=subprocess.Popen([str(binaries[0]),'--kill-on-exit','-f',str(executable),str(data),str(marker)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(200):
  if marker.exists():break
  time.sleep(.05)
 assert marker.exists();pids=[int(x) for x in marker.read_text().split()];process.kill();process.wait(timeout=5)
 def alive(pid):
  try:return pathlib.Path('/proc/'+str(pid)+'/stat').read_text().split(') ',1)[1][0]!='Z'
  except FileNotFoundError:return False
 for _ in range(100):
  if not any(alive(pid) for pid in pids):break
  time.sleep(.05)
 assert not any(alive(pid) for pid in pids),'strace left its owned tracees alive'
 archive=output/'strace-7.2-linux-x64.tgz'
 with open(archive,'wb') as file,gzip.GzipFile(fileobj=file,mode='wb',mtime=0,filename='') as compressed,tarfile.open(fileobj=compressed,mode='w') as packed:
  for path in sorted(package.rglob('*')):
   name='strace-7.2/'+path.relative_to(package).as_posix();info=packed.gettarinfo(str(path),arcname=name);info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
   if path.is_file():
    with open(path,'rb') as handle:packed.addfile(info,handle)
   else:packed.addfile(info)
 receipt={'schema':1,'scope':'Native source build and Linux ptrace feasibility; adapter/model gates pending','sourceSha256':sha(source),'buildScriptSha256':sha(__file__),'deadlineSourceSha256':sha(repository/'skills/ghidra-coordinator/runtime/native/deadline-exec.c'),'platform':platform.platform(),'compiler':run(['cc','--version']).decode().splitlines()[0],'libc':run(['getconf','GNU_LIBC_VERSION']).decode().strip(),'version':run([str(binaries[0]),'-V']).decode(),'reproducibleBinary':True,'binarySha256':sha(binaries[0]),'deadlineSha256':sha(package/'bin/deadline-exec'),'archiveSha256':sha(archive),'archiveSize':archive.stat().st_size,'checks':{'actualOwnedConfigRead':True,'killOnExitTerminatesDescendants':True,'systemLibcOnly':True},'dependencies':dependency}
 (output/'strace-build.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
