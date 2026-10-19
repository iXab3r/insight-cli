#!/usr/bin/env node
import {timingSpan} from '@eyeauras/cli-factory';
const {runHosted}=await timingSpan('bootstrap.ipc-module',()=>import('@eyeauras/cli-factory-ipc'));
const {createDefinition}=await timingSpan('bootstrap.domain-modules',()=>import('./cli.js'));
process.exitCode = await runHosted({ entryPoint: import.meta.url, createDefinition });
