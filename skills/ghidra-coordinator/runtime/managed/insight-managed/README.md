# First-party managed metadata capability

This internal helper is not a standalone application or a separately installed tool.
It runs under an existing private .NET 10 runtime. dnlib 4.5.0 is packaged with its full
MIT license, exact NuGet URL/SHA and locked dependency metadata. Original library source:
https://github.com/0xd4d/dnlib/tree/v4.5.0

`build-managed-helper.mjs` requires maintainer SDK 10.0.303, builds twice from independent
temporary directories, compares all four shipped artifacts and records source/binary
hashes. Consumers require no SDK/compiler. PDB loading is disabled; target assemblies
are parsed as metadata and are never loaded for execution. Comparisons use static
structure, not semantic equivalence, and retain tokens scoped to each exact input.

Method selection supports a case-insensitive short managed-name substring, independent of
namespace, declaring type and signature. The existing full-name filter remains case-sensitive.
Both filters apply before pagination; an overview/type query rejects a method-name filter.
