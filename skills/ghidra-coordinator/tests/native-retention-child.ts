import {Workspace} from '../src/workspace.js';
import type {Artifact} from '../src/artifacts.js';

// A real process exit inside the SQLite transaction, or immediately after its commit. No native worker is launched.
const [directory,request,snapshotJson,phase]=process.argv.slice(2);
if(!directory||!request||!snapshotJson||!['before','after'].includes(phase??''))throw Error('Retention interruption fixture arguments required');
const workspace=new Workspace(directory,'default'),context=workspace.contextById(workspace.request(request).context);
if(phase==='before')(workspace as unknown as {writeRequest:()=>never}).writeRequest=()=>process.exit(81);
workspace.retainNativeDisposal(context,context.generation,context.nativeCheckout!,JSON.parse(snapshotJson) as Artifact,request);
process.exit(82);
