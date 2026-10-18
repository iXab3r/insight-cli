# Packaged structured binary helper

First-party MIT C++ facade linked statically against unmodified LIEF 1.0.0 (Apache-2.0)
and its published dependencies. Consumer installation needs no compiler or SDK. Only
system libc++/libSystem are linked dynamically. Native host profile: macOS14+ ARM64.

The maintainer builder consumes the exact hash-bound SDK and original full source
archive, extracts its bundled JSON header and builds twice in independent temporary
directories with Apple clang 17.0.0/SDK26.0, reproducible linking and canonical source
paths. Output hashes must match; source, original notices and binary hashes are checked
before packaging. The library/source mirror URLs and original URLs are both recorded.

All original available vendored notices are retained, including an explicit build/test
superset. JSON's missing archive license is retained from its exact upstream version.
The span source's original attribution/declaration and the official Boost license it
references are retained; its old short source revision no longer resolves upstream.
The full original header remains available in the mirrored LIEF source archive.

Queries cover parsed structures and selected native linkage; malformed/omitted tables
are never proof of global absence. The only edit assigns the original two-byte PE
subsystem field on a new copy, verifies LIEF readback and proves every other byte equal.
It never executes target code, repairs signatures or rewrites arbitrary binary data.
