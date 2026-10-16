#!/usr/bin/env node
import { runHosted } from '@eyeauras/cli-factory-ipc';
import { createDefinition } from './cli.js';
process.exitCode = await runHosted({ entryPoint: import.meta.url, createDefinition });
