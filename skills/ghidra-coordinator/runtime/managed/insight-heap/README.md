# First-party structured managed heap capability

ClrMD 4.2.751201 and its locked dependency closure are implementation libraries behind
`dotnet-dump query`, not new applications. Consumers reuse a private .NET 10 runtime and
an explicitly matching native CoreCLR DAC; no SDK is required. No live attachment,
expression evaluation, automatic file lookup or symbol server is enabled.

`dependencies.json` records all exact original package SHA256/content hashes, source
commits and full retained license notices. Microsoft authentication libraries are
upstream transitive dependencies; this helper never creates credentials or symbol
server clients. The no-files locator returns no external image or downloaded symbol.

The maintainer builder compiles twice in independent temporary directories with SDK
10.0.303, locked restore and canonical source paths, compares every shipped output,
and records source, notices and binary hashes. Parsing runs under the common owned
process deadline. Heap scan, field, string, stack and output bounds remain explicit.
