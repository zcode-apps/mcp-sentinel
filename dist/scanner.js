import fetch from 'node-fetch';
export class MCPSentinel {
    async scan(url) {
        const results = [];
        console.error(`[MCP Sentinel] Scanning ${url}...`);
        // 1. Check if MCP endpoint is accessible
        const baseUrl = url.replace(/\/$/, '');
        // 2. Try MCP Initialize handshake
        let serverInfo = null;
        try {
            const initResponse = await this.sendMCPRequest(baseUrl, {
                jsonrpc: '2.0',
                id: 1,
                method: 'initialize',
                params: {
                    protocolVersion: '2024-11-05',
                    clientInfo: {
                        name: 'mcp-sentinel',
                        version: '0.1.0'
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
        }
        catch (error) {
            results.push({
                type: 'MCP_PROTOCOL_ERROR',
                severity: 'medium',
                description: `MCP endpoint not responding properly: ${error.message}`,
                recommendation: 'Verify the URL is a valid MCP server endpoint'
            });
            return results;
        }
        // 3. Check for authentication bypass
        const authResult = await this.checkAuthBypass(baseUrl);
        if (authResult)
            results.push(authResult);
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
                    evidence: tools.map((t) => t.name)
                });
                // Check for dangerous tools
                for (const tool of tools) {
                    const toolCheck = this.analyzeTool(tool);
                    if (toolCheck)
                        results.push(toolCheck);
                }
            }
        }
        catch (error) {
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
                    if (pathCheck)
                        results.push(pathCheck);
                }
            }
        }
        catch (error) {
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
                    if (promptCheck)
                        results.push(promptCheck);
                }
            }
        }
        catch (error) {
            // Prompts might not be implemented
        }
        return results;
    }
    async sendMCPRequest(url, body) {
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
            });
            const data = await response.json();
            return data;
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async checkAuthBypass(url) {
        // Try to access without authentication
        try {
            const response = await this.sendMCPRequest(url, {
                jsonrpc: '2.0',
                id: 'auth-check',
                method: 'initialize',
                params: {
                    protocolVersion: '2024-11-05',
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
        }
        catch (error) {
            // Server requires auth - good
        }
        return null;
    }
    analyzeTool(tool) {
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
                    severity: severity,
                    description: `Tool '${toolName}' may allow ${type.replace(/_/g, ' ').toLowerCase()}`,
                    evidence: { toolName, toolDesc, inputSchema: tool.inputSchema },
                    recommendation: `Review tool '${toolName}' for proper input validation and access controls`
                };
            }
        }
        return null;
    }
    checkPathTraversal(resource) {
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
    analyzePrompt(prompt) {
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
}
