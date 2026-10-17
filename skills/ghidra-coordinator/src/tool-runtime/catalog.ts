import {readFileSync} from 'node:fs';
import type {ToolArtifact} from './definition.js';
import {fail} from '../model.js';
const catalog=JSON.parse(readFileSync(new URL('../../../runtime/tool-catalog.json',import.meta.url),'utf8')) as Record<string,ToolArtifact>;
/** Expected bytes come from the installed package, never a replaceable remote manifest. */
export function catalogArtifact(sha256:string):ToolArtifact {
 const a=catalog[sha256];
 const dnspy=a?.url==='https://github.com/dnSpyEx/dnSpy/releases/download/v6.6.0/dnSpy-net-win64.zip'&&a.sha256==='8ed48f165dc355e869f3a0037ad4f9216147f995a5ae0258b296eeef1f73aab0'&&a.delivery?.publisher==='dnSpyEx'&&a.delivery.termsUrl==='https://visualstudio.microsoft.com/license-terms/mlt552233/';
 const microsoft=a?.delivery?.publisher==='Microsoft'&&new URL(a.delivery.termsUrl).hostname==='learn.microsoft.com'&&new URL(a.delivery.termsUrl).protocol==='https:'&&new URL(a.url).protocol==='https:'&&['download.sysinternals.com','windbg.download.prss.microsoft.com'].includes(new URL(a.url).hostname);
 const vendor=a?.delivery?.kind==='vendor-direct'&&Boolean(a.delivery.reason)&&(dnspy||microsoft);
 if(!a||a.sha256!==sha256||!(a.url.startsWith('https://github.com/iXab3r/insight-cli/releases/download/tool-')||vendor)||!Number.isSafeInteger(a.size)||a.size!<1)
  fail('binding','Pinned tool distribution is absent or invalid in the retained catalog.');
 return {...a};
}
