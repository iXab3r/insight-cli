import {Store}from'../src/store.js';import{Coordinator,type Publisher}from'../src/coordinator.js';
const directory=process.argv[2]!;const store=new Store(directory,'default','ghidra://127.0.0.1:14100');
try{await new Coordinator(store,{} as Publisher).recover(store.batches()[0]!.id);process.exitCode=2;}
catch(e){process.stdout.write(JSON.stringify({code:(e as {code:string}).code}));process.exitCode=1;}
finally{store.close();}
