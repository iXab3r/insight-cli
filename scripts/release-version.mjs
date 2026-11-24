// Set the one product version everywhere it is committed: package, lock entry and skill headings.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {readFile,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const workspace='skills/ghidra-coordinator',packageName='@eyeauras/insight-cli';
const skillVersions=JSON.parse(readFileSync(new URL('../skills/ghidra-coordinator/runtime/toolbox.json',import.meta.url),'utf8')).skills.map(skill=>[`${workspace}/${skill.path}`,skill.title]);
export const versionFiles=[`${workspace}/package.json`,'package-lock.json',...skillVersions.map(([path])=>path)];
export async function setVersion(root,version){
  assert.match(version??'',/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/,'Expected a stable version');
  const originals=Object.fromEntries(await Promise.all(versionFiles.map(async path=>[path,(await readFile(join(root,path),'utf8')).replaceAll('\r\n','\n')])));
  const pkg=JSON.parse(originals[versionFiles[0]]),lock=JSON.parse(originals['package-lock.json']),previous=pkg.version;
  assert.equal(pkg.name,packageName);assert.equal(lock.packages[workspace].version,previous);
  pkg.version=version;lock.packages[workspace].version=version;
  const result={[versionFiles[0]]:JSON.stringify(pkg,null,2)+'\n','package-lock.json':JSON.stringify(lock,null,2)+'\n'};
  for(const [path,title] of skillVersions){
    const heading=`# ${title} ${previous}`,lines=originals[path].split('\n'),at=lines.indexOf(heading);
    assert.ok(at>=0,`Missing original skill heading: ${path}`);
    lines[at]=`# ${title} ${version}`;result[path]=lines.join('\n');
  }
  for(const path of versionFiles)await writeFile(join(root,path),result[path]);
  return {previous,version};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))console.log(JSON.stringify(await setVersion(process.cwd(),process.argv[2])));
