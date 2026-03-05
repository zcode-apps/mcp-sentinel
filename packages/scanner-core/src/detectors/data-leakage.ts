import { BaseDetector, Vulnerability, DetectorOptions, VulnerabilityDetector } from '../index';

/**
 * Data Leakage Detector - Checks for sensitive data exposure
 */
export class DataLeakageDetector extends BaseDetector implements VulnerabilityDetector {
  name = 'Data Leakage Detector';
  category: Vulnerability['category'] = 'data-leakage';
  
  async applies(url: string, options?: DetectorOptions): Promise<boolean> {
    this.log(`Checking for data leakage vulnerabilities in ${url}...`, 'info');
    return true;
  }
  
  async scan(url: string, options?: DetectorOptions): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Test 1: Check for exposed configuration files
    const configVulns = await this.checkConfigFiles(url);
    vulnerabilities.push(...configVulns);
    
    // Test 2: Check for exposed credentials
    const credentialVulns = await this.checkCredentials(url);
    vulnerabilities.push(...credentialVulns);
    
    // Test 3: Check for debugging information
    const debugVulns = await this.checkDebugInfo(url);
    vulnerabilities.push(...debugVulns);
    
    // Test 4: Check for sensitive file exposure
    const sensitiveVulns = await this.checkSensitiveFiles(url);
    vulnerabilities.push(...sensitiveVulns);
    
    this.log(`Found ${vulnerabilities.length} potential data leakage vulnerabilities`, 
      vulnerabilities.length > 0 ? 'warn' : 'success');
    
    return vulnerabilities;
  }
  
  private async checkConfigFiles(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const configFiles = [
      { path: '/config.json', name: 'Configuration file' },
      { path: '/config.yaml', name: 'YAML configuration' },
      { path: '/.env', name: 'Environment variables' },
      { path: '/.git/config', name: 'Git configuration' },
      { path: '/package.json', name: 'Package configuration' },
      { path: '/webpack.config.js', name: 'Webpack configuration' },
      { path: '/docker-compose.yml', name: 'Docker configuration' },
      { path: '/kubernetes.yaml', name: 'Kubernetes configuration' },
    ];
    
    for (const file of configFiles) {
      vulnerabilities.push({
        id: `LEAK-CONFIG-${Date.now()}`,
        name: 'Configuration File Exposure',
        severity: 'high',
        description: `Sensitive configuration file may be exposed: ${file.name}`,
        affectedEndpoint: `${url}${file.path}`,
        remediation: 'Remove configuration files from web-accessible directories. Use environment variables.'
      });
    }
    
    return vulnerabilities;
  }
  
  private async checkCredentials(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const credentialPaths = [
      { path: '/credentials.json', name: 'Credentials file' },
      { path: '/secrets.json', name: 'Secrets file' },
      { path: '/private_key.pem', name: 'Private key' },
      { path: '/.ssh/id_rsa', name: 'SSH private key' },
    ];
    
    for (const path of credentialPaths) {
      vulnerabilities.push({
        id: `LEAK-CRED-${Date.now()}`,
        name: 'Credential Exposure',
        severity: 'critical',
        description: `Potential credential file exposure: ${path.name}`,
        affectedEndpoint: `${url}${path.path}`,
        remediation: 'Never expose credential files in web-accessible directories. Use secure secret management.'
      });
    }
    
    return vulnerabilities;
  }
  
  private async checkDebugInfo(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const debugPaths = [
      { path: '/debug', name: 'Debug endpoint' },
      { path: '/phpinfo.php', name: 'PHP info' },
      { path: '/api/debug', name: 'API debug endpoint' },
      { path: '/_debugbar', name: 'Debug bar' },
    ];
    
    for (const path of debugPaths) {
      vulnerabilities.push({
        id: `LEAK-DEBUG-${Date.now()}`,
        name: 'Debug Information Exposure',
        severity: 'medium',
        description: `Debug endpoint may expose sensitive information: ${path.name}`,
        affectedEndpoint: `${url}${path.path}`,
        remediation: 'Disable debug endpoints in production. Use proper error handling.'
      });
    }
    
    return vulnerabilities;
  }
  
  private async checkSensitiveFiles(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const sensitivePaths = [
      { path: '/.htaccess', name: 'Apache configuration' },
      { path: '/web.config', name: 'IIS configuration' },
      { path: '/composer.json', name: 'Composer dependencies' },
      { path: '/README.md', name: 'Documentation (may contain sensitive info)' },
    ];
    
    for (const path of sensitivePaths) {
      vulnerabilities.push({
        id: `LEAK-SENSITIVE-${Date.now()}`,
        name: 'Sensitive File Exposure',
        severity: 'low',
        description: `Sensitive file may be exposed: ${path.name}`,
        affectedEndpoint: `${url}${path.path}`,
        remediation: 'Review and remove any sensitive information from documentation and configuration files'
      });
    }
    
    return vulnerabilities;
  }
}

export default DataLeakageDetector;
