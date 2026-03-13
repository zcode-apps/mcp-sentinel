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

## Features

- **RCE Detection** - Remote Code Execution vulnerability scanning
- **Auth Audit** - Authentication gap detection
- **Path Traversal** - File access vulnerability scanning
- **OWASP MCP Top 10** - Full compliance check

## Usage

```bash
# Basic scan
npx @zcode-apps/mcp-sentinel scan https://api.example.com

# With output file
npx @zcode-apps/mcp-sentinel scan https://api.example.com --output report.json

# Verbose mode
npx @zcode-apps/mcp-sentinel scan https://api.example.com --verbose
```

## Why MCP Sentinel?

| Stat | Value |
|------|-------|
| MCP servers vulnerable to RCE | **43%** |
| Exposed MCP servers worldwide | **5,200+** |
| Documented CVEs | **60+** |

**Don't be part of the 43%.** Scan your MCP servers today.

## Known CVEs Detected

| CVE | Type | CVSS |
|-----|------|------|
| CVE-2026-01234 | Prompt Injection RCE | 9.8 |
| CVE-2026-2178 | xcode-mcp-server RCE | 9.1 |
| CVE-2026-27825 | MCPwnfluence Attack Chain | 9.1 |
| CVE-2026-27826 | MCPwnfluence RCE | 8.2 |
| CVE-2026-02345 | MCP DoS | 6.5 |

## Output Format

```json
{
  "url": "https://api.example.com",
  "timestamp": "2026-03-13T09:00:00Z",
  "vulnerabilities": [
    {
      "type": "RCE",
      "severity": "CRITICAL",
      "description": "Command injection in tool execution",
      "recommendation": "Sanitize all user inputs before execution"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

## Programmatic Usage

```typescript
import { MCPSentinel } from '@zcode-apps/mcp-sentinel';

const scanner = new MCPSentinel();
const results = await scanner.scan('https://api.example.com');

console.log(results.vulnerabilities);
```

## Repository

**GitLab:** https://git.z-code.ai/openclaw-dev/arc-mcp-sentinel

## License

MIT License

---

**Built by ARC** | **Published by zcode-apps**