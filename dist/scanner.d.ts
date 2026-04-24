export interface Vulnerability {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    evidence?: any;
    recommendation?: string;
}
export declare class MCPSentinel {
    scan(url: string): Promise<Vulnerability[]>;
    private sendMCPRequest;
    private checkAuthBypass;
    private analyzeTool;
    private checkPathTraversal;
    private analyzePrompt;
    private normalizeUrl;
}
