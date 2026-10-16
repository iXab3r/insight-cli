import type {Parameter} from './arguments.js';
interface SdkOperation {operation:string;group:string;name:string;description:string;write?:boolean;pair?:boolean;params:Parameter[]}
const str=(name:string,required=true):Parameter=>({name,type:'string',required});
const at=(name='address'):Parameter=>({...str(name),semantic:'address'});
const json=(name:string,type='object',required=true):Parameter=>({name,type,required});
const count=(name:string,value:string):Parameter=>({name,type:'integer',required:false,default:value});
const empty=(name:string):Parameter=>({...str(name,false),default:'',allowEmpty:true});
const bool=(name:string):Parameter=>({name,type:'boolean',required:false,default:'false'});
const original=[str('name'),at('expect_start'),{...count('expect_size','1'),required:true},str('expect_sha256')];
export const sdkOperations:SdkOperation[]=[
  {operation:'type-layout',group:'types',name:'layout',description:'Read native packing, alignment, bitfields, settings and source archive identity',params:[str('path')]},
  {operation:'type-structure',group:'types',name:'define-layout',description:'Create a native structure with packing/alignment/bitfields; replace only an explicitly selected empty placeholder',write:true,params:[str('path'),json('fields','array'),{name:'packing',type:'integer',required:false,default:'0'},{name:'alignment',type:'integer',required:false,default:'0'},bool('replace_placeholder')]},
  {operation:'type-settings',group:'types',name:'set-settings',description:'Edit default settings by actual native definition names; null clears an explicit setting',write:true,params:[str('path'),json('settings')]},
  {operation:'type-archive-import',group:'types',name:'archive-import',description:'Import explicit GDT type paths with archive identity and saved layout verification',write:true,params:[str('input'),json('types','array')]},
  {operation:'changes',group:'changes',name:'compare',description:'Categorized native ProgramDiff of two saved private contexts; does not merge',pair:true,params:[{...json('categories','array',false),default:'["bytes","comments","symbols","functions"]'},count('max_ranges','100'),count('timeout_seconds','30')]},
  {operation:'block-state',group:'memory',name:'block-state',description:'Read exact block layout and bounded full-content digest',params:[str('name')]},
  {operation:'assembly-preview',group:'assembly',name:'preview',description:'Assemble in this program language and processor context without writing',params:[at(),json('instructions','array')]},
  {operation:'patch-bytes',group:'memory',name:'patch-bytes',description:'Replace equal-length bytes only when the expected bytes match; clears overlapping listing',write:true,params:[at(),str('expect_hex'),str('bytes_hex')]},
  {operation:'assemble',group:'assembly',name:'apply',description:'Apply context-aware assembly with exact byte preconditions; clears overlapping listing',write:true,params:[at(),str('expect_hex'),json('instructions','array')]},
  {operation:'split-block',group:'memory',name:'split-block',description:'Split one initialized block while verifying all original bytes and layout',write:true,params:[...original,at('split_address'),str('new_name')]},
  {operation:'move-block',group:'memory',name:'move-block',description:'Move a block only when its original layout and bytes match',write:true,params:[...original,at()]},
  {operation:'join-blocks',group:'memory',name:'join-blocks',description:'Join adjacent compatible blocks with independent content and size preconditions',write:true,params:[str('name'),str('second_name'),str('expect_sha256'),str('second_sha256'),{...count('expect_size','1'),required:true},{...count('second_size','1'),required:true}]},
  {operation:'context-read',group:'processor-context',name:'read',description:'Read bounded register-value ranges in the saved program context',params:[str('register'),at(),{...at('end_address'),required:false},count('limit','100')]},
  {operation:'context-set',group:'processor-context',name:'set',description:'Set a processor register value over at most 65536 bytes; requires unchanged-base publication',write:true,params:[str('register'),at(),at('end_address'),str('value')]},
  {operation:'context-clear',group:'processor-context',name:'clear',description:'Remove an explicit processor register value over at most 65536 bytes',write:true,params:[str('register'),at(),at('end_address')]},
  {operation:'namespace-list',group:'namespaces',name:'list',description:'List direct namespace/class children with explicit visited-symbol budget',params:[empty('parent'),count('limit','100'),count('max_scan','10000')]},
  {operation:'namespace-create',group:'namespaces',name:'create',description:'Create an explicit namespace or class below an existing parent',write:true,params:[empty('parent'),str('name'),bool('class')]},
  {operation:'namespace-update',group:'namespaces',name:'update',description:'Rename or reparent an ordinary namespace/class without recursive deletion',write:true,params:[str('path'),str('new_name'),empty('parent')]},
  {operation:'namespace-delete',group:'namespaces',name:'delete',description:'Delete one empty ordinary namespace/class',write:true,params:[str('path')]},
  {operation:'external-list',group:'externals',name:'list',description:'Read library identities or structured locations in one explicit library',params:[empty('library'),count('limit','100')]},
  {operation:'library-create',group:'externals',name:'create-library',description:'Create a named external library in the private program',write:true,params:[str('name')]},
  {operation:'library-update',group:'externals',name:'update-library',description:'Rename an external library or change its logical project path',write:true,params:[str('name'),str('new_name',false),str('path',false)]},
  {operation:'library-delete',group:'externals',name:'delete-library',description:'Delete an empty external library',write:true,params:[str('name')]},
  {operation:'external-create',group:'externals',name:'create-location',description:'Create an external label/function with an optional memory address',write:true,params:[str('library'),str('label'),{...at(),required:false},bool('function')]},
  {operation:'external-update',group:'externals',name:'update-location',description:'Rename/update one unambiguous external location',write:true,params:[str('library'),str('label'),str('new_label'),{...at(),required:false}]},
  {operation:'external-delete',group:'externals',name:'delete-location',description:'Delete one unambiguous external location, refusing retained dependencies',write:true,params:[str('library'),str('label')]},
  {operation:'decompiler-ir',group:'decompiler',name:'ir',description:'Read bounded typed SSA P-code with explicit simplification/options and completion diagnostics',params:[at(),{...str('simplification',false),default:'decompile'},count('max_ops','1000'),count('timeout_seconds','30'),bool('c_code'),{...json('options','object',false),default:'{}'}]},
];
export const sdkWrites=new Set(sdkOperations.filter(v=>v.write).map(v=>'/sdk/'+v.operation));
