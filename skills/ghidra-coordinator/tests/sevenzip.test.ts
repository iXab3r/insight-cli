import test from 'node:test';import assert from 'node:assert/strict';
import {parseArchiveListing,safeArchivePath} from '../src/sevenzip.js';
test('container inventory rejects ambiguous multiline records and unsafe recovery paths',()=>{
 const items=parseArchiveListing('Path = lib/subject.dll\nFolder = -\nSize = 4096\nEncrypted = -\nAttributes =  -rw-r--r--\n\n');assert.equal(items[0]!.size,4096);assert.equal(items[0]!.path,'lib/subject.dll');
 for(const value of ['Path = x\nnewline\nFolder = -\nSize = 1','Path = x\nPath = y\nFolder = -\nSize = 1','Path = x\nFolder = -\nSize = NaN'])assert.throws(()=>parseArchiveListing(value));
 for(const path of ['../escape','/absolute','C:/file','x\\file','x/../file','x//file','x\nfile'])assert.throws(()=>safeArchivePath(path));
 assert.equal(safeArchivePath('configuration/settings.json'),'configuration/settings.json');
});
