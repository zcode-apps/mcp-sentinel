# MCP Sentinel

Security scanner for Model Context Protocol (MCP) servers. Detects vulnerabilities before attackers do.

## Installation

```bash
# Run directly with npx (recommended)
npx @zcode-apps/mcp-sentinel scan https://your-mcp-server.com

# Or install globally
npm install -g @zcode-apps/mcp-sentinel
mcp-sentinel scan https://your-mcp-server.com
```

## Usage

```bash
# Basic scan (text output)
npx @zcode-apps/mcp-sentinel scan https://api.example.com/mcp

# JSON output
npx @zcode-apps/mcp-sentinel scan https://api.example.com/mcp --json

# Verbose mode (show evidence)
npx @zcode-apps/mcp-sentinel scan https://api.example.com/mcp --verbose
```

## Features

- **MCP Protocol Detection** - Verifies valid MCP endpoints
- **Authentication Bypass** - Checks for missing auth
- **Dangerous Tool Detection** - Finds tools with RCE, file access, SQL risks
- **Path Traversal** - Detects unsafe resource URIs
- **Prompt Injection Risks** - Identifies dynamic prompt vulnerabilities

## Output Example

```
🔍 MCP Sentinel - Security Scanner

Target: https://api.example.com/mcp
──────────────────────────────────────────────────

🔵 INFO:

   [INFO]
   MCP Server detected: my-mcp-server v1.0.0
   
   [INFO]
   Found 5 exposed tools: ["get_weather", "run_command", "read_file"]

🟠 HIGH SEVERITY:

   [AUTH_BYPASS]
   MCP server accepts unauthenticated connections
   💡 Recommendation: Implement authentication on MCP endpoints

──────────────────────────────────────────────────
📊 SUMMARY:
   Critical: 0
   High:     1
   Medium:   0
   Info:     2
```

## Why MCP Sentinel?

| Stat | Value |
|------|-------|
| MCP servers vulnerable to RCE | **43%** |
| Exposed MCP servers worldwide | **5,200+** |
| Documented CVEs | **60+** |

**Don't be part of the 43%.** Scan your MCP servers today.

## Repository

**GitLab:** https://git.z-code.ai/openclaw-dev/arc-mcp-sentinel  
**npm:** https://www.npmjs.com/package/@zcode-apps/mcp-sentinel

## License

MIT License

---

**Built by ARC**