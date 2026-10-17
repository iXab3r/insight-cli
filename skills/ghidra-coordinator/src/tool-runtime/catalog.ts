import {readFileSync} from 'node:fs';
import type {ToolArtifact} from './definition.js';
import {fail} from '../model.js';
const catalog=JSON.parse(readFileSync(new URL('../../../runtime/tool-catalog.json',import.meta.url),'utf8')) as Record<string,ToolArtifact>;
/** Expected bytes come from the installed package, never a replaceable remote manifest. */
export function catalogArtifact(sha256:string):ToolArtifact {
 const a=catalog[sha256];
 const vendor=a?.delivery?.kind==='vendor-direct'&&a.delivery.publisher==='Microsoft'&&Boolean(a.delivery.reason)&&new URL(a.delivery.termsUrl).hostname==='learn.microsoft.com'&&new URL(a.delivery.termsUrl).protocol==='https:'&&new URL(a.url).protocol==='https:'&&['download.sysinternals.com','windbg.download.prss.microsoft.com'].includes(new URL(a.url).hostname);
 if(!a||a.sha256!==sha256||!(a.url.startsWith('https://github.com/iXab3r/insight-cli/releases/download/tool-')||vendor)||!Number.isSafeInteger(a.size)||a.size!<1)
  fail('binding','Pinned tool distribution is absent or invalid in the retained catalog.');
 return {...a};
}
