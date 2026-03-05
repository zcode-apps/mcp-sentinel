import chalk from 'chalk';

/**
 * Scanner core module
 * Provides the foundation for MCP security scanning
 */

export type ScanResult = {
  url: string;
  timestamp: Date;
  vulnerabilities: Vulnerability[];
  score: number;
};

export type Vulnerability = {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  cve?: string;
  affectedEndpoint: string;
  proof?: string;
  remediation: string;
  category: 'rce' | 'auth' | 'path-traversal' | 'data-leakage' | 'owasp';
};

export type DetectorOptions = {
  timeout?: number;
  verbose?: boolean;
};

export interface VulnerabilityDetector {
  name: string;
  category: Vulnerability['category'];
  
  /**
   * Check if this detector applies to the target
   */
  applies(url: string, options?: DetectorOptions): Promise<boolean>;
  
  /**
   * Run the vulnerability check
   */
  scan(url: string, options?: DetectorOptions): Promise<Vulnerability[]>;
}

/**
 * Base class for all vulnerability detectors
 */
export abstract class BaseDetector implements VulnerabilityDetector {
  constructor(protected options: DetectorOptions = {}) {}
  
  abstract name: string;
  abstract category: Vulnerability['category'];
  
  async applies(url: string, opts?: DetectorOptions): Promise<boolean> {
    return true;
  }
  
  protected log(message: string, level: 'info' | 'warn' | 'error' | 'success' = 'info'): void {
    const timestamp = new Date().toISOString();
    let prefix = '';
    
    switch (level) {
      case 'info':
        prefix = chalk.blue('[INFO]');
        break;
      case 'warn':
        prefix = chalk.yellow('[WARN]');
        break;
      case 'error':
        prefix = chalk.red('[ERROR]');
        break;
      case 'success':
        prefix = chalk.green('[SUCCESS]');
        break;
    }
    
    console.log(`${chalk.gray(timestamp)} ${prefix} ${message}`);
  }
  
  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
