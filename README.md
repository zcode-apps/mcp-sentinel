# MCP Sentinel

Security scanner for Model Context Protocol (MCP) servers. The current CLI focuses on fast endpoint validation and heuristic risk discovery for exposed tools, resources, and prompts.

![MCP Sentinel Screenshot](https://raw.githubusercontent.com/zcode-apps/mcp-sentinel/main/image.jpg)

## Installation

```bash
# Run directly with npx
npx @zcode-apps/mcp-sentinel scan https://your-mcp-server.com/mcp

# Or install globally
npm install -g @zcode-apps/mcp-sentinel
mcp-sentinel scan https://your-mcp-server.com/mcp
```

## Usage

```bash
# Human-readable output
npx @zcode-apps/mcp-sentinel scan https://api.example.com/mcp

# JSON output for pipelines
npx @zcode-apps/mcp-sentinel scan https://api.example.com/mcp --json

# Include evidence in terminal output
npx @zcode-apps/mcp-sentinel scan https://api.example.com/mcp --verbose
```

## What It Checks Today

- MCP handshake support via `initialize`
- Unauthenticated access to the endpoint
- Exposed tools returned by `tools/list`
- Heuristic risk classification for dangerous tool names, descriptions, and input schemas
- Suspicious resource URIs from `resources/list`
- Prompts that appear to accept dynamic user input from `prompts/list`

## Scope And Limits

MCP Sentinel is currently a lightweight remote audit tool. It does not attempt active exploitation, deep semantic analysis of tool implementations, or full compliance validation against a broader security standard.

The `packages/` directory in this repository contains earlier prototype detector work that is not wired into the published CLI. Those packages are intentionally marked as private to avoid shipping unfinished detector logic by accident.

## Example Output

```text
🔍 MCP Sentinel - Security Scanner

Target: https://api.example.com/mcp
──────────────────────────────────────────────────

🔵 INFO:

   [INFO]
   MCP Server detected: my-mcp-server v1.0.0

   [INFO]
   Found 5 exposed tools

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

## Roadmap

- Better HTTP and JSON-RPC error classification
- Optional report export formats
- Safer detector coverage backed by reproducible fixtures
- CI smoke tests against local MCP test servers

## Repository

- GitHub: [zcode-apps/mcp-sentinel](https://github.com/zcode-apps/mcp-sentinel)
- npm: [@zcode-apps/mcp-sentinel](https://www.npmjs.com/package/@zcode-apps/mcp-sentinel)

## License

MIT

---

Built by Sebastian Zang
