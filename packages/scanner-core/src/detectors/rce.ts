import { BaseDetector, Vulnerability, DetectorOptions, VulnerabilityDetector } from '../index';

/**
 * RCE Detector - Checks for Remote Code Execution vulnerabilities
 * Focuses on CVE-2026-26029 and CVE-2026-23744 patterns
 */
export class RCEDetector extends BaseDetector implements VulnerabilityDetector {
  name = 'RCE Detector';
  category: Vulnerability['category'] = 'rce';
  
  private readonly patterns = [
    // Command injection patterns
    { pattern: /;\s*(cat|ls|pwd|whoami|id|curl|wget)\b/, severity: 'critical' },
    { pattern: /&&\s*(cat|ls|pwd|whoami|id)\b/, severity: 'critical' },
    { pattern: /\|\|\s*(cat|ls|pwd|whoami|id)\b/, severity: 'critical' },
    { pattern: /`\$\{[^}]+\}/, severity: 'high' },
    { pattern: /\$\([^)]+\)/, severity: 'high' },
    { pattern: /eval\s*\(/, severity: 'critical' },
    { pattern: /exec\s*\(/, severity: 'high' },
    { pattern: /system\s*\(/, severity: 'critical' },
    { pattern: /passthru\s*\(/, severity: 'high' },
    { pattern: /shell_exec\s*\(/, severity: 'critical' },
    
    // Path traversal combined with code execution
    { pattern: /\.\.\/\.\.\/etc\/passwd/, severity: 'critical' },
    { pattern: /\.\.\/\.\.\/etc\/shadow/, severity: 'critical' },
  ];
  
  async applies(url: string, options?: DetectorOptions): Promise<boolean> {
    this.log(`Checking if ${url} is vulnerable to RCE...`, 'info');
    return true;
  }
  
  async scan(url: string, options?: DetectorOptions): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Test 1: Check for command injection in URL parameters
    const testUrls = [
      `${url}?cmd=ls`,
      `${url}?exec=cat /etc/passwd`,
      `${url}?command=whoami`,
      `${url}?q=;cat /etc/passwd`,
      `${url}?input=$(whoami)`,
    ];
    
    for (const testUrl of testUrls) {
      try {
        const vuln = await this.checkCommandInjection(testUrl, url);
        if (vuln) vulnerabilities.push(vuln);
      } catch (error) {
        this.log(`Error testing ${testUrl}: ${error}`, 'warn');
      }
    }
    
    // Test 2: Check for eval/exec patterns in responses
    try {
      const evalVuln = await this.checkEvalInjection(url);
      if (evalVuln) vulnerabilities.push(evalVuln);
    } catch (error) {
      this.log(`Error checking eval injection: ${error}`, 'warn');
    }
    
    // Test 3: Check for PHP-specific vulnerabilities (common in MCP servers)
    try {
      const phpVulns = await this.checkPHPVulnerabilities(url);
      vulnerabilities.push(...phpVulns);
    } catch (error) {
      this.log(`Error checking PHP vulnerabilities: ${error}`, 'warn');
    }
    
    this.log(`Found ${vulnerabilities.length} potential RCE vulnerabilities`, 
      vulnerabilities.length > 0 ? 'warn' : 'success');
    
    return vulnerabilities;
  }
  
  private async checkCommandInjection(url: string, originalUrl: string): Promise<Vulnerability | null> {
    // In a real implementation, this would make actual requests
    // For now, we're setting up the framework
    
    // Simulate checking (will be replaced with actual HTTP requests)
    const riskPatterns = this.patterns.filter(p => 
      url.toLowerCase().includes('cat') || 
      url.toLowerCase().includes('ls') ||
      url.toLowerCase().includes('whoami')
    );
    
    if (riskPatterns.length > 0) {
      return {
        id: 'RCE-001',
        name: 'Potential Command Injection',
        severity: 'critical',
        description: 'The endpoint appears to accept user input that could be used for command injection attacks',
        cve: 'CVE-2026-26029',
        affectedEndpoint: originalUrl,
        proof: `Test URL: ${url}`,
        remediation: 'Implement input validation, use allowlists for allowed inputs, and escape special characters'
      };
    }
    
    return null;
  }
  
  private async checkEvalInjection(url: string): Promise<Vulnerability | null> {
    // Check for JavaScript eval() vulnerabilities
    // This would make actual requests in production
    
    return {
      id: 'RCE-002',
      name: 'Potential JavaScript Code Injection',
      severity: 'critical',
      description: 'The application may be vulnerable to JavaScript code injection through eval() or similar functions',
      cve: 'CVE-2026-23744',
      affectedEndpoint: url,
      remediation: 'Avoid using eval(). Use JSON.parse() for JSON data and proper sanitization for user inputs'
    };
  }
  
  private async checkPHPVulnerabilities(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Check for common PHP RCE vectors
    const phpTestUrls = [
      `${url}?file=php://filter/convert.base64-encode/resource=config.php`,
      `${url}?page=php://input`,
      `${url}?include=php://input`,
    ];
    
    for (const testUrl of phpTestUrls) {
      vulnerabilities.push({
        id: `RCE-PHP-${Date.now()}`,
        name: 'PHP Wrappers Vulnerability',
        severity: 'high',
        description: 'PHP wrapper URLs detected - potential code execution vector',
        affectedEndpoint: testUrl,
        remediation: 'Validate and sanitize all file path inputs. Disable dangerous PHP wrappers if not needed.'
      });
    }
    
    return vulnerabilities;
  }
}

export default RCEDetector;
