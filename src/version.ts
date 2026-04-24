import { readFileSync } from 'node:fs';

type PackageMetadata = {
  version?: string;
};

function readPackageVersion(): string {
  try {
    const packageJsonUrl = new URL('../package.json', import.meta.url);
    const packageJson = readFileSync(packageJsonUrl, 'utf8');
    const metadata = JSON.parse(packageJson) as PackageMetadata;
    return metadata.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const APP_VERSION = readPackageVersion();
export const MCP_PROTOCOL_VERSION = '2024-11-05';
