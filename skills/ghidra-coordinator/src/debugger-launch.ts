/** Preserve the pinned Ghidra launcher except its one explicit local LLDB run command. */
export function debuggerLaunchArguments(arguments_:readonly string[],stopAtEntry:boolean,ownedPython?:string):string[]{
  const result=[...arguments_];
  if(ownedPython){
    const imports=result.flatMap((value,index)=>index>0&&['-o','--one-line'].includes(result[index-1]!)&&value==='script import os, ghidralldb'?[index]:[]);
    if(imports.length!==1)throw Error('Pinned LLDB launcher must supply exactly one adapter import');
    result[imports[0]!]="script import sys,os; sys.path.insert(0,"+JSON.stringify(ownedPython)+"); import ghidralldb,ghidralldb.methods; os._exit(253) if os.path.realpath(ghidralldb.methods.__file__) != "+JSON.stringify(ownedPython+'/ghidralldb/methods.py')+" else None; print('Insight owned LLDB adapter verified')";
  }
  if(!stopAtEntry)return result;
  const launches=result.flatMap((value,index)=>index>0&&['-o','--one-line'].includes(result[index-1]!)&&value.startsWith('process launch')?[index]:[]);
  if(launches.length!==1||!['process launch','process launch --stop-at-entry'].includes(result[launches[0]!]!))throw Error('Pinned LLDB launcher must supply exactly one supported launch command');
  result[launches[0]!]='process launch --stop-at-entry';return result;
}
