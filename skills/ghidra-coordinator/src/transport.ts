import { fail, object } from './model.js';
import {parseDomainJson} from './json.js';

export interface Descriptor { path: string; method: string; params: { name: string; source: string }[] }
/** The pinned GhidraMCP HTTP side of a dedicated bridge. No discovery by project name. */
export class HttpBridge {
  private schema?: Map<string, Descriptor>;
  constructor(readonly endpoint: string, private fetch: typeof globalThis.fetch = globalThis.fetch, private signal?: AbortSignal, private token?: string) {
    const url = new URL(endpoint);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.pathname !== '/')
      fail('binding', 'Worker bridge must use an explicit loopback HTTP port.');
  }
  private async request(path: string, method: string, query: Record<string, unknown>, body: Record<string, unknown>): Promise<unknown> {
    const url = new URL(path, this.endpoint);
    for (const [name, value] of Object.entries(query)) url.searchParams.set(name, String(value));
    let response: Response;
    try {
      response = await this.fetch(url, { method, redirect: 'error', signal: this.signal ? AbortSignal.any([this.signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000), headers: { ...(this.token ? { Authorization: 'Bearer ' + this.token } : {}), ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) }, ...(method === 'POST' ? { body: JSON.stringify(body) } : {}) });
    } catch { fail('transport', 'The dedicated Ghidra bridge request did not complete.'); }
    if (!response.ok) fail('remote', 'Ghidra bridge rejected the operation.');
    // Bound even a chunked/malformed service response; never persist raw payloads as logs.
    const reader = response.body?.getReader();
    if (!reader) fail('malformed', 'Ghidra bridge returned an empty body.');
    const chunks: Uint8Array[] = []; let length = 0;
    try { for (;;) { const next = await reader.read(); if (next.done) break; length += next.value.byteLength; if (length > 1024 * 1024) fail('limit', 'Ghidra response exceeded one MiB.'); chunks.push(next.value); } }
    finally { await reader.cancel().catch(() => {}); }
    const text = Buffer.concat(chunks).toString('utf8');
    let result: unknown;
    try { result = parseDomainJson(text); } catch { result = text; }
    if (result && typeof result === 'object' && !Array.isArray(result)) {
      const o = object(result);
      if (o.error || o.success === false || o.status === 'error') {
        const reason=typeof o.error==='string'&&o.error.length<=1024&&!o.error.includes('\0')?o.error:undefined;
        fail('remote',reason?'Ghidra: '+reason:'Ghidra operation failed.');
      }
    }
    return result;
  }
  async instance() { return object(await this.request('/mcp/instance_info', 'GET', {}, {})); }
  async descriptor(path:string):Promise<Descriptor> {
    if (!this.schema) {
      const schema = object(await this.request('/mcp/schema', 'GET', {}, {}));
      if (!Array.isArray(schema.tools)) fail('malformed', 'Ghidra schema omitted its tool descriptors.');
      this.schema = new Map(schema.tools.map(value => { const d = object(value) as unknown as Descriptor; return [d.path, d]; }));
    }
    const tool = this.schema.get(path);
    if (!tool || !['GET', 'POST'].includes(tool.method) || !Array.isArray(tool.params)) fail('schema', 'Required Ghidra operation is missing from the observed schema.');
    return tool;
  }
  async call(path: string, params: Record<string, unknown> = {}): Promise<unknown> {
    const tool=await this.descriptor(path);
    const query: Record<string, unknown> = {}, body: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(params)) {
      const param = tool.params.find(p => p.name === name);
      if (!param) fail('schema', 'Required Ghidra operation parameter is missing from the observed schema.');
      (param.source === 'body' ? body : query)[name] = value;
    }
    return this.request(path, tool.method, query, body);
  }
}

export function decodeMcp(result: unknown): unknown {
  const r = object(result);
  if (r.isError === true || !Array.isArray(r.content)) fail('remote', 'MCP bridge reported failure or malformed content.');
  const content = r.content.filter(x => x && typeof x === 'object' && x.type === 'text');
  if (content.length !== 1 || typeof content[0]?.text !== 'string' || content[0].text.length > 1024 * 1024)
    fail('malformed', 'Expected one bounded MCP text result.');
  let value: unknown;
  try { value = parseDomainJson(content[0].text); } catch { value = content[0].text; }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const o = object(value);
    if (o.error || o.success === false) fail('remote', 'MCP result content reports failure.');
  }
  return value;
}
