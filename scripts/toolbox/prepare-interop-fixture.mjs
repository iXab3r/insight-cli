// Maintainer fixture build; research consumers need no compiler or SDK.
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
assert.equal(process.env.INSIGHT_NATIVE_DISPOSABLE,'1');
const [output,dotnet,clang,lldLink]=process.argv.slice(2);assert.ok(lldLink);await mkdir(output,{recursive:true,mode:0o700});
const native=resolve(output,'PolicyNative.dll'),managed=resolve(output,'out/OwnedInterop.dll');
await writeFile(join(output,'policy.c'),'__declspec(dllexport) int quote_total(int count) { return count * 9 + 10; }\n');
execFileSync(clang,['--target=x86_64-pc-windows-msvc','-O0','-c',join(output,'policy.c'),'-o',join(output,'policy.obj')]);
execFileSync(lldLink,['/dll','/noentry','/timestamp:0','/out:'+native,'/implib:'+join(output,'PolicyNative.lib'),join(output,'policy.obj')]);
await writeFile(join(output,'OwnedInterop.csproj'),'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><AssemblyName>OwnedInterop</AssemblyName><DebugType>none</DebugType></PropertyGroup></Project>');
await writeFile(join(output,'Policy.cs'),'using System.Runtime.InteropServices;namespace OwnedInterop;public static class Policy{[DllImport("PolicyNative.dll",EntryPoint="quote_total",CallingConvention=CallingConvention.Cdecl,ExactSpelling=true)]public static extern int NativeQuote(int count);}\n');
execFileSync(dotnet,['build',join(output,'OwnedInterop.csproj'),'--configuration','Release','--output',join(output,'out'),'--artifacts-path',join(output,'build'),'--nologo'],{stdio:'pipe'});
const hash=async file=>createHash('sha256').update(await readFile(file)).digest('hex');await writeFile(join(output,'fixture.json'),JSON.stringify({schema:1,managed,native,managedSha256:await hash(managed),nativeSha256:await hash(native),module:'PolicyNative.dll',entryPoint:'quote_total'},null,2)+'\n');console.log('Owned managed/native interop pair prepared');
