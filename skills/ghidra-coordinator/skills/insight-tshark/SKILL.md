---
name: insight-tshark
description: Inspect an offline PCAP or PCAPNG with insight-cli tshark to identify protocols, HTTP/DNS/TLS fields, packet evidence and reconstructed TCP/UDP streams. Use for captured traffic questions; live acquisition and TLS decryption are separate tasks.
---

# Insight TShark 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation. Keep HOME, profile and owner state;
see [host execution permissions](references/agent-execution.md). Unknown mutations need
request/status recovery, never blind retry.

Keep the project's evidence format. This tool reads an immutable capture; it does not
start packet capture, install BPF helpers, change network settings or contact DNS servers.
The delivered native profile is macOS ARM64, macOS 14+.

1. `insight-cli tshark status --json` checks readiness. `tshark install` delivers the
   pinned console subset and full notices from our GitHub Release. `download` caches it;
   `install --archive tshark-4.6.9-macos-console.tgz --offline` uses local bytes.
   `install --executable /Applications/Wireshark.app/Contents/MacOS/tshark` accepts the
   exact pinned 4.6.9 runtime. It copies only known console/data files into owned storage,
   excluding external GUI/plugins; it fingerprints the original and owned family.
   Uninstall preserves the external distribution, original capture and saved research.
2. Start with `tshark inspect traffic.pcap --json`. The returned target identifies the
   captured bytes. Overview counts protocols and streams. `--view packets --filter
   'http.request' --limit 20` returns actual frame numbers and selected protocol fields;
   `--view streams` returns native TCP/UDP stream IDs and participating IPs/frame numbers.
   Address lists may include encapsulated layers; they are not asserted endpoint pairs.
3. Follow evidence with `tshark inspect --target TARGET --view packet --frame 4 --json`
   for full native packet JSON, or `--view follow --transport tcp --stream 0 --json` for
   ordered native reassembly chunks. Follow returns endpoint labels, chunk direction and
   hex bytes. Decode bytes with any suitable external tool and keep the frame/stream and
   input SHA alongside the conclusion. Stream IDs belong to one capture revision.
4. Inventory/filters/follow inspect at most the first 10000 frames of an input up to
   64 MiB. `complete: false` means later frames and absent matches remain unknown.
   Pagination applies after the display filter; it does not extend that read boundary.
   Packet view reads up to its explicit frame (maximum one million), without claiming
   whole-capture coverage. Follow has no display filter; use its native stream ID.
   Native output/deadlines remain bounded. Encrypted or missing traffic is not evidence
   of absent application behavior; no arbitrary tap, Lua script or TLS key is executed.
5. `--output research/protocol.json` saves the full bounded view to a new ordinary file;
   existing files are preserved. Use `artifacts save` when a checkpoint is useful.
   `tools processes --tool tshark --all` retains native run diagnostics. Stop/kill only
   owned process records; a failed read is not automatically replayed or recollected.

Generated `tshark inspect --help` owns exact flags. For packet filters, Wireshark's display
filter language applies; it is not a capture/BPF filter.
