import fetch, { RequestInit } from 'node-fetch';
import { APP_VERSION, MCP_PROTOCOL_VERSION } from './version.js';

export interface Vulnerability {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence?: any;
  recommendation?: string;
}

type ConnectionIssue = {
  type: string;
  severity: Vulnerability['severity'];
  description: string;
  recommendation: string;
};

export class MCPSentinel {
  async scan(url: string): Promise<Vulnerability[]> {
    const results: Vulnerability[] = [];
    
    const normalizedUrl = this.normalizeUrl(url);

    console.error(`[MCP Sentinel] Scanning ${normalizedUrl}...`);

    // 1. Check if MCP endpoint is accessible
    const baseUrl = normalizedUrl.replace(/\/$/, '');
    
    // 2. Try MCP Initialize handshake
    let serverInfo: any = null;
    try {
      const initResponse = await this.sendMCPRequest(baseUrl, {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          clientInfo: {
            name: 'mcp-sentinel',
            version: APP_VERSION
          },
          capabilities: {}
        }
      });
      
      if (initResponse.result) {
        serverInfo = initResponse.result;
        results.push({
          type: 'INFO',
          severity: 'low',
          description: `MCP Server detected: ${serverInfo.serverInfo?.name || 'Unknown'} v${serverInfo.serverInfo?.version || 'Unknown'}`,
          evidence: serverInfo
        });
      }
    } catch (error: any) {
      results.push(this.classifyConnectionIssue(error));
      return results;
    }

    // 3. Check for authentication bypass
    const authResult = await this.checkAuthBypass(baseUrl);
    if (authResult) results.push(authResult);

    // 4. List and analyze tools
    try {
      const toolsResponse = await this.sendMCPRequest(baseUrl, {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list'
      });

      if (toolsResponse.result?.tools) {
        const tools = toolsResponse.result.tools;
        results.push({
          type: 'INFO',
          severity: 'low',
          description: `Found ${tools.length} exposed tools`,
          evidence: tools.map((t: any) => t.name)
        });

        // Check for dangerous tools
        for (const tool of tools) {
          const toolCheck = this.analyzeTool(tool);
          if (toolCheck) results.push(toolCheck);
        }
      }
    } catch (error: any) {
      results.push({
        type: 'TOOLS_ACCESS_ERROR',
        severity: 'medium',
        description: `Could not enumerate tools: ${error.message}`
      });
    }

    // 5. Check for resource exposure
    try {
      const resourcesResponse = await this.sendMCPRequest(baseUrl, {
        jsonrpc: '2.0',
        id: 3,
        method: 'resources/list'
      });

      if (resourcesResponse.result?.resources) {
        const resources = resourcesResponse.result.resources;
        
        // Check for path traversal
        for (const resource of resources) {
          const pathCheck = this.checkPathTraversal(resource);
          if (pathCheck) results.push(pathCheck);
        }
      }
    } catch (error: any) {
      // Resources might not be implemented
    }

    // 6. Check for prompt injection vulnerabilities
    try {
      const promptsResponse = await this.sendMCPRequest(baseUrl, {
        jsonrpc: '2.0',
        id: 4,
        method: 'prompts/list'
      });

      if (promptsResponse.result?.prompts) {
        for (const prompt of promptsResponse.result.prompts) {
          const promptCheck = this.analyzePrompt(prompt);
          if (promptCheck) results.push(promptCheck);
        }
      }
    } catch (error: any) {
      // Prompts might not be implemented
    }

    return results;
  }

  private async sendMCPRequest(url: string, body: any): Promise<any> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal
      } as RequestInit);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }

      const rawBody = await response.text();
      if (!rawBody.trim()) {
        throw new Error('Empty response body');
      }

      let data: any;
      try {
        data = JSON.parse(rawBody);
      } catch {
        throw new Error('Response was not valid JSON');
      }

      if (data.error) {
        const message = typeof data.error.message === 'string'
          ? data.error.message
          : 'Unknown JSON-RPC error';
        throw new Error(`JSON-RPC error: ${message}`);
      }

      return data;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async checkAuthBypass(url: string): Promise<Vulnerability | null> {
    // Try to access without authentication
    try {
      const response = await this.sendMCPRequest(url, {
        jsonrpc: '2.0',
        id: 'auth-check',
        method: 'initialize',
        params: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          clientInfo: { name: 'unauthenticated', version: '1.0.0' },
          capabilities: {}
        }
      });

      if (response.result && !response.error) {
        return {
          type: 'AUTH_BYPASS',
          severity: 'high',
          description: 'MCP server accepts unauthenticated connections',
          recommendation: 'Implement authentication on MCP endpoints'
        };
      }
    } catch (error) {
      // Server requires auth - good
    }
    return null;
  }

  private analyzeTool(tool: any): Vulnerability | null {
    const dangerousPatterns = [
      { pattern: /exec|eval|run|execute/i, severity: 'critical', type: 'COMMAND_INJECTION_RISK' },
      { pattern: /file|read|write|delete/i, severity: 'high', type: 'FILE_ACCESS_RISK' },
      { pattern: /shell|bash|cmd|powershell/i, severity: 'critical', type: 'SHELL_COMMAND_RISK' },
      { pattern: /sql|database|query/i, severity: 'high', type: 'SQL_INJECTION_RISK' },
      { pattern: /http|fetch|request/i, severity: 'medium', type: 'SSRF_RISK' },
    ];

    const toolName = tool.name || '';
    const toolDesc = tool.description || '';
    const inputSchema = JSON.stringify(tool.inputSchema || {});

    for (const { pattern, severity, type } of dangerousPatterns) {
      if (pattern.test(toolName) || pattern.test(toolDesc) || pattern.test(inputSchema)) {
        return {
          type,
          severity: severity as any,
          description: `Tool '${toolName}' may allow ${type.replace(/_/g, ' ').toLowerCase()}`,
          evidence: { toolName, toolDesc, inputSchema: tool.inputSchema },
          recommendation: `Review tool '${toolName}' for proper input validation and access controls`
        };
      }
    }

    return null;
  }

  private checkPathTraversal(resource: any): Vulnerability | null {
    const uri = resource.uri || '';
    
    // Check for path traversal patterns
    if (uri.includes('..') || uri.includes('~') || uri.includes('/etc/') || uri.includes('/var/')) {
      return {
        type: 'PATH_TRAVERSAL',
        severity: 'high',
        description: `Resource URI may be vulnerable to path traversal: ${uri}`,
        recommendation: 'Validate and sanitize resource URIs'
      };
    }

    return null;
  }

  private analyzePrompt(prompt: any): Vulnerability | null {
    const name = prompt.name || '';
    const description = prompt.description || '';

    // Check for prompt injection risks
    if (description.toLowerCase().includes('user input') || 
        description.toLowerCase().includes('dynamic')) {
      return {
        type: 'PROMPT_INJECTION_RISK',
        severity: 'medium',
        description: `Prompt '${name}' accepts dynamic input`,
        recommendation: 'Implement prompt injection guards'
      };
    }

    return null;
  }

  private normalizeUrl(url: string): string {
    try {
      return new URL(url).toString();
    } catch {
      throw new Error(`Invalid URL: ${url}`);
    }
  }

  private classifyConnectionIssue(error: Error): ConnectionIssue {
    const message = error.message || 'Unknown connection error';

    if (message.includes('HTTP 401') || message.includes('HTTP 403')) {
      return {
        type: 'AUTH_REQUIRED',
        severity: 'low',
        description: `Endpoint is reachable but requires authentication: ${message}`,
        recommendation: 'Retry the scan with valid authentication or verify the endpoint access policy.'
      };
    }

    if (message.includes('HTTP 404')) {
      return {
        type: 'ENDPOINT_NOT_FOUND',
        severity: 'medium',
        description: `No MCP endpoint was found at this URL: ${message}`,
        recommendation: 'Verify the MCP path. Many servers expose MCP under a dedicated route such as /mcp.'
      };
    }

    if (message.includes('HTTP 405')) {
      return {
        type: 'METHOD_NOT_ALLOWED',
        severity: 'medium',
        description: `Endpoint is reachable but does not accept MCP requests at this route: ${message}`,
        recommendation: 'Verify that the URL points to an MCP JSON-RPC endpoint that accepts POST requests.'
      };
    }

    if (message.includes('Response was not valid JSON') || message.includes('Empty response body')) {
      return {
        type: 'NON_MCP_RESPONSE',
        severity: 'medium',
        description: `Endpoint responded, but not with a valid MCP JSON-RPC payload: ${message}`,
        recommendation: 'Verify that the target is an MCP endpoint and not a regular website or API route.'
      };
    }

    if (message.includes('Invalid URL')) {
      return {
        type: 'INVALID_URL',
        severity: 'medium',
        description: `The provided target URL is invalid: ${message}`,
        recommendation: 'Provide a full URL including protocol and path.'
      };
    }

    return {
      type: 'MCP_PROTOCOL_ERROR',
      severity: 'medium',
      description: `MCP endpoint not responding properly: ${message}`,
      recommendation: 'Verify the URL is a valid MCP server endpoint and that the service is reachable.'
    };
  }
}
