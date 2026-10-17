# Local Unicode loader correction

Pinned dnSpyEx 6.6.0 (`e2bada24b1c63683f41bdc0ae2b0119c686ce88a`)
uses an ANSI `LoadLibraryEx` declaration in
`Extensions/dnSpy.Debugger/dnSpy.Debugger.DotNet.CorDebug/dndbg/Engine/NativeMethods.cs`.
Its Core debugger consequently cannot load dbgshim from a Unicode installation path.

The first-party typed extension locally rewrites only the pinned GPL engine's import
into `LoadLibraryExW`, Unicode charset, exact spelling and LPWStr first argument.
It preserves metadata tokens, assembly identity and strong-name signing. The bundled
596-byte `upstream-public-build.snk` is dnSpy's intentionally public reproducible source
build key, NOT a secret credential. Original source:
https://github.com/dnSpyEx/dnSpy/blob/e2bada24b1c63683f41bdc0ae2b0119c686ce88a/dnSpy.snk
SHA256: 6f84725f0755f4428cc8c95c5d1d0997445a057266bf810dc090607d4a2d0ae6.
The readback verifies the original public key matches before signing and the assembly
identity/import after writing. A different input engine or key is refused.

Preparation executes once under the native owned Job; the original engine is replaced
only after that bootstrap process exits. Managed software is prepared in installation
staging. External software remains byte-for-byte unchanged: only the 867 known pinned
vendor files are copied into owned installation storage, prepared and fingerprinted.
Both external originals and the owned execution tree are checked before every use.
Uninstall removes the owned copy and preserves the external original and research.
The upstream archive is cached unmodified. No modified vendor DLL is redistributed.
The upstream GPL text and corresponding source remain identified by the vendor bundle
and the pinned source repository. The patch logic itself is supplied as Bridge.cs.
