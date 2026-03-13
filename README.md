# MCP Sentinel

Security scanner for Model Context Protocol (MCP) servers. Detects vulnerabilities before attackers do.

## Installation

```bash
# Run directly with npx (recommended)
npx mcp-security-scanner scan https://your-mcp-server.com

# Or install globally
npm install -g mcp-security-scanner
mcp-sentinel scan https://your-mcp-server.com
```

## Features

- **MCP Protocol Detection** - Verifies valid MCP endpoints
- **Authentication Bypass** - Checks for missing auth
- **Dangerous Tool Detection** - Finds tools with RCE, file access, SQL risks
- **Path Traversal** - Detects unsafe resource URIs
- **Prompt Injection Risks** - Identifies dynamic prompt vulnerabilities
- **OWASP MCP Top 10** - Covers common MCP security issues

## Usage

```bash
# Basic scan (text output)
npx mcp-security-scanner scan https://api.example.com/mcp

# JSON output
npx mcp-security-scanner scan https://api.example.com/mcp --output json

# Verbose mode (show evidence)
npx mcp-security-scanner scan https://api.example.com/mcp --verbose
```

## Output Example

```
🔍 MCP Sentinel - Security Scanner

Target: https://api.example.com/mcp
──────────────────────────────────────────────────

🟠 HIGH SEVERITY:

   [AUTH_BYPASS]
   MCP server accepts unauthenticated connections
   💡 Recommendation: Implement authentication on MCP endpoints

🔵 INFO:

   [INFO]
   MCP Server detected: my-mcp-server v1.0.0
   
   [INFO]
   Found 5 exposed tools: ["get_weather", "run_command", "read_file", "query_db", "fetch_url"]

──────────────────────────────────────────────────
📊 SUMMARY:
   Critical: 0
   High:     1
   Medium:   0
   Info:     2
```

## Vulnerability Types

| Type | Severity | Description |
|------|----------|-------------|
| `COMMAND_INJECTION_RISK` | Critical | Tool allows command execution |
| `SHELL_COMMAND_RISK` | Critical | Tool has shell/bash access |
| `FILE_ACCESS_RISK` | High | Tool can read/write files |
| `SQL_INJECTION_RISK` | High | Tool has database access |
| `AUTH_BYPASS` | High | No authentication required |
| `PATH_TRAVERSAL` | High | Unsafe file path access |
| `SSRF_RISK` | Medium | Tool can make HTTP requests |
| `PROMPT_INJECTION_RISK` | Medium | Dynamic prompt input |

## Why MCP Sentinel?

| Stat | Value |
|------|-------|
| MCP servers vulnerable to RCE | **43%** |
| Exposed MCP servers worldwide | **5,200+** |
| Documented CVEs | **60+** |

**Don't be part of the 43%.** Scan your MCP servers today.

## Programmatic Usage

```typescript
import { MCPSentinel } from 'mcp-security-scanner';

const scanner = new MCPSentinel();
const results = await scanner.scan('https://api.example.com/mcp');

console.log(results);
// [
//   { type: 'AUTH_BYPASS', severity: 'high', description: '...' }
// ]
```

## Repository

**GitLab:** https://git.z-code.ai/openclaw-dev/arc-mcp-sentinel  
**npm:** https://www.npmjs.com/package/mcp-security-scanner

## License

MIT License

---

**Built by ARC**