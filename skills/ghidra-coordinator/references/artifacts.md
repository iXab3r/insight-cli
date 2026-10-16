# Save ordinary research materials

`insight-cli artifacts save <path> --json` saves a file or a settled directory tree in
the selected profile's AppData. It needs Factory Update permission and does not require
Ghidra, Java, authentication, target/session selectors or evidence metadata. Relative input
paths resolve against the caller's working directory. Use `--help` for generated syntax.

Write notes and useful external-tool outputs as ordinary files while investigating. When
the selected files are no longer being edited, save one file, a completed worker subfolder
or the whole research folder. For example:

```sh
insight-cli artifacts save ./research --json
```

The receipt has `state: "saved"`, `path`, `kind` (`file` or `directory`), `files`, `bytes`
and `sha256`. `path` points to an ordinary browsable copy with the source basename and
relative layout. Empty files and empty directories are retained. File count counts regular
files; byte count counts their contents. A file's SHA-256 hashes its bytes; a directory's
SHA-256 hashes its canonical manifest of relative paths, kinds, file lengths and hashes.
The manifest is stored beside the content, outside the returned directory.

The service copies and syncs data before publishing the completed snapshot. Failure does
not return a successful receipt or expose a partial completed snapshot. Source edits made
after a successful save do not change the copy. Treat saved copies as retained snapshots;
edit the original research folder and save a new copy for another checkpoint. Each call
creates a new saved copy, including a repeated call after a lost response.

Keep a directory stable for the save: detected concurrent edits are rejected. Copying
several files is not an atomic filesystem snapshot of a directory that other agents keep
changing. Symbolic links and special files are rejected rather than followed or silently
omitted. Select the actual intended regular file/directory. Do not save a directory that
contains the destination materials store. Traversal supports at most 100,000 entries and
128 levels to bound inventory memory and recursion. Disk/permission failures return nonzero.

The saved bytes establish what was retained. Commands, tool versions and interpretations
written in a note remain the author's statements, not execution attestations. No upload,
tool execution or Ghidra publication is performed by saving materials.

Profile deletion/configuration invalidation is blocked while retained materials exist,
as with retained research work. Close tool contexts normally; preserve snapshots separately
if retiring a profile. There is no automatic registration, cleanup policy, graph database
or additional read API: read the receipt's path with normal file tools.
