#!/usr/bin/env node
import { Command } from 'commander';
import { MCPSentinel } from './scanner.js';
const program = new Command();
program
    .name('mcp-sentinel')
    .description('MCP Security Scanner - Detects vulnerabilities in MCP servers')
    .version('0.1.0');
program
    .command('scan <url>')
    .description('Scan an MCP server endpoint for security vulnerabilities')
    .option('-o, --output <format>', 'Output format: json, text', 'text')
    .option('-v, --verbose', 'Show detailed output', false)
    .action(async (url, options) => {
    const scanner = new MCPSentinel();
    if (options.output === 'text') {
        console.log(`\n🔍 MCP Sentinel - Security Scanner\n`);
        console.log(`Target: ${url}\n`);
        console.log('─'.repeat(50));
    }
    const results = await scanner.scan(url);
    if (options.output === 'json') {
        console.log(JSON.stringify(results, null, 2));
        return;
    }
    // Text output
    if (results.length === 0) {
        console.log('✅ No vulnerabilities found.\n');
        return;
    }
    // Group by severity
    const critical = results.filter(r => r.severity === 'critical');
    const high = results.filter(r => r.severity === 'high');
    const medium = results.filter(r => r.severity === 'medium');
    const low = results.filter(r => r.severity === 'low');
    if (critical.length > 0) {
        console.log('\n🔴 CRITICAL VULNERABILITIES:');
        critical.forEach(v => printVulnerability(v, options.verbose));
    }
    if (high.length > 0) {
        console.log('\n🟠 HIGH SEVERITY:');
        high.forEach(v => printVulnerability(v, options.verbose));
    }
    if (medium.length > 0) {
        console.log('\n🟡 MEDIUM SEVERITY:');
        medium.forEach(v => printVulnerability(v, options.verbose));
    }
    if (low.length > 0) {
        console.log('\n🔵 INFO:');
        low.forEach(v => printVulnerability(v, options.verbose));
    }
    // Summary
    console.log('\n' + '─'.repeat(50));
    console.log('📊 SUMMARY:');
    console.log(`   Critical: ${critical.length}`);
    console.log(`   High:     ${high.length}`);
    console.log(`   Medium:   ${medium.length}`);
    console.log(`   Info:     ${low.length}`);
    console.log('');
});
function printVulnerability(v, verbose) {
    console.log(`\n   [${v.type}]`);
    console.log(`   ${v.description}`);
    if (verbose && v.evidence) {
        console.log(`   Evidence: ${JSON.stringify(v.evidence, null, 2).split('\n').join('\n   ')}`);
    }
    if (v.recommendation) {
        console.log(`   💡 Recommendation: ${v.recommendation}`);
    }
}
program.parse();
