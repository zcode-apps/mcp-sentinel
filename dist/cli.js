#!/usr/bin/env node
import { Command } from 'commander';
import { MCPSentinel } from './scanner.js';
const program = new Command();
program
    .name('mcp-sentinel')
    .description('MCP Security Scanner - Scans for vulnerabilities');
program
    .command('scan <url>')
    .description('Scan a URL for vulnerabilities')
    .action(async (url) => {
    const scanner = new MCPSentinel();
    const results = await scanner.scan(url);
    console.log(JSON.stringify(results, null, 2));
});
program.parse();
