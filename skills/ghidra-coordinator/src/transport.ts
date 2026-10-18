import { fail, object } from './model.js';
import {parseDomainJson} from './json.js';
import {CliError} from '@eyeauras/cli-factory';

export interface Descriptor { path: string; method: string; params: { name: string; source: string }[] }
/** The pinned GhidraMCP HTTP side of a dedicated bridge. No discovery by project name. */
export class HttpBridge {
  private schema?: Map<string, Descriptor>;
  constructor(readonly endpoint: string, private fetch: typeof globalThis.fetch = globalThis.fetch, private signal?: AbortSignal, private token?: string,private timeoutMilliseconds?:number,private saveTimeoutMilliseconds=120000) {
    const url = new URL(endpoint);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.pathname !== '/')
      fail('binding', 'Worker bridge must use an explicit loopback HTTP port.');
    if(!Number.isSafeInteger(saveTimeoutMilliseconds)||saveTimeoutMilliseconds<1000||saveTimeoutMilliseconds>3600000)fail('invalid','Save timeout is outside the supported bound.');
    if(timeoutMilliseconds!==undefined&&(!Number.isSafeInteger(timeoutMilliseconds)||timeoutMilliseconds<1||timeoutMilliseconds>1800000))fail('invalid','Bridge timeout is outside the supported bound.');
  }
  private async request(path: string, method: string, query: Record<string, unknown>, body: Record<string, unknown>): Promise<unknown> {
    const url = new URL(path, this.endpoint);
    // Import includes synchronous auto-analysis. Keep discovery/ordinary requests short,
    // while allowing a real executable to finish its first analysis without losing the reply.
    const saving=path==='/save_program'||path==='/export_program';
    const timeoutMilliseconds=this.timeoutMilliseconds??(saving?this.saveTimeoutMilliseconds:path==='/import_file'?600000:30000);
    const signal=this.signal?AbortSignal.any([this.signal,AbortSignal.timeout(timeoutMilliseconds)]):AbortSignal.timeout(timeoutMilliseconds);
    const transportFailure=()=>{
      if(this.signal?.aborted)fail('cancelled',`Ghidra request ${path} was cancelled; its outcome may require reconciliation.`,{operation:path});
      if(signal.aborted)fail('timeout',`Ghidra request ${path} exceeded ${timeoutMilliseconds/1000} seconds; its outcome may require reconciliation.${saving?' Configure profile saveSeconds before future work; inspect sessions status and never replay an uncertain script.':''}`,{operation:path,timeoutMilliseconds,...(saving?{phase:'save',budgetSetting:'saveSeconds',outcome:'unknown'}:{})});
      fail('transport',`Ghidra request ${path} did not complete; its outcome may require reconciliation.`,{operation:path});
    };
    for (const [name, value] of Object.entries(query)) url.searchParams.set(name, String(value));
    let response: Response;
    try {
      response = await this.fetch(url, { method, redirect: 'error', signal, headers: { ...(this.token ? { Authorization: 'Bearer ' + this.token } : {}), ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) }, ...(method === 'POST' ? { body: JSON.stringify(body) } : {}) });
    } catch { return transportFailure(); }
    if (!response.ok) fail('remote', 'Ghidra bridge rejected the operation.');
    // Bound even a chunked/malformed service response; never persist raw payloads as logs.
    const reader = response.body?.getReader();
    if (!reader) fail('malformed', 'Ghidra bridge returned an empty body.');
    const chunks: Uint8Array[] = []; let length = 0;
    try { for (;;) { const next = await reader.read(); if (next.done) break; length += next.value.byteLength; if (length > 1024 * 1024) fail('limit', 'Ghidra response exceeded one MiB.'); chunks.push(next.value); } }
    catch(error){if(error instanceof CliError)throw error;return transportFailure();}
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
