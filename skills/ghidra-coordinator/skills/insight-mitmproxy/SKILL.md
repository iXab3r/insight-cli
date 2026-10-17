---
name: insight-mitmproxy
description: Record, inspect and compare HTTP request/response evidence with insight-cli mitmproxy. Use when an owned client can explicitly use a loopback proxy; read native flow archives or HAR without replaying traffic. System interception and global certificate trust are outside this facade.
---

# Insight mitmproxy 0.2.0

If local help/status reports AppData or IPC access denied, retry that **read-only probe**
with the agent host's normal permission escalation. Keep HOME, profile and owner state;
see [host execution permissions](references/agent-execution.md). Unknown mutations need
request/status recovery, never blind retry.

Keep the project's RE and evidence format. This facade uses a private HTTP proxy on
macOS 15+ ARM64. A client must explicitly opt into its endpoint; installing the tool
does not intercept traffic or install a system proxy, certificate or Network Extension.

1. Check `insight-cli mitmproxy status --json`. `mitmproxy install` delivers the pinned
   standalone runtime and full notices from our source-complete GitHub Release.
   `download` prepares its cache; `install --archive mitmproxy-12.2.3-macos-arm64.tgz
   --offline` uses matching local bytes. `install --executable
   /path/mitmproxy.app/Contents/MacOS/mitmdump` selects a complete external bundle, creates an owned execution copy and
   fingerprints its adjacent runtime. `doctor` checks the pinned version.
2. Start an observation window alongside the owned client:
   `mitmproxy record --listen-port 8877 --duration-seconds 15 --output research/window.mitm
   --json`. In another invocation, `mitmproxy status --json` reports each active capture's
   `ready`, `endpoint`, public `caCertificate` and owned process ID. Wait for readiness;
   then configure only the selected client to use that endpoint. The record command
   returns after its bounded window. A client, curl or another external tool remains free
   to run outside insight-cli. Client NO_PROXY/bypass rules can exclude a destination;
   adjust only that client when necessary. Native stop/kill uses `tools processes stop/kill PROCESS`.
3. For HTTPS, the selected client must explicitly trust the returned public CA certificate
   in its own process. An owned origin with a private CA additionally needs
   `record --upstream-ca public-root.pem`. This copies only a public PEM certificate;
   no global trust change occurs. TLS failures remain explicit partial observations.
   CA private keys stay in profile storage: checkpoint the requested report/archive, not
   the private configuration directory. Certificate pinning may prevent HTTP decoding.
4. `mitmproxy inspect research/window.mitm --json` gives a bounded overview.
   `--view flows --method POST --url-contains /quote --limit 5` returns matching requests,
   status, headers, body SHA256 and a base64 body prefix. Follow a native flow UUID with
   `--view flow --flow-id UUID`. `--target ID` reuses immutable captured bytes; native
   archives and HAR are read without reconnecting or replaying their requests.
   `--output research/http.json` writes all bounded selected rows to a new ordinary file.
5. `mitmproxy compare before.mitm after.mitm --json` compares literal method/URL and
   occurrence order, selected body SHA256, status and error fields. Volatile headers and
   timestamps are excluded. Review the linked flow IDs: occurrence matching is an aid,
   not proof that two requests had the same cause. Missing bodies and partial inputs
   remain unknown; unmatched rows in a partial capture do not prove absence.
6. The proxy limits native bodies to 1 MiB each and the archive to 64 MiB. Reads accept
   inputs up to 64 MiB; `--max-flows` bounds scan/record count to 1000. Returned bodies
   default to 1024 bytes; `--body-bytes` can request 0–65536. The JSON report is bounded
   to 8 MiB, and pagination follows method/URL selection. Base64 contains native raw
   HTTP content; apply Content-Encoding separately if needed. WebSocket payload,
   generic TCP/UDP and whole-machine absence are not claimed.
7. A failed/interrupted window retains its archive and diagnostics. Inspect the retained
   bytes explicitly; a readable prefix returns `partial`. There is no automatic
   recollection or traffic replay. `artifacts save` can retain ordinary completed files.
   Uninstall preserves research and any external distribution.

Generated `mitmproxy ... --help` owns exact flags. Use TShark when the question needs
packet-level evidence rather than decoded HTTP observations.
