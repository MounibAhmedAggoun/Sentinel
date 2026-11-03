import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

interface PackageJson {
  version: string;
}

const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url));

/** The scanner package version, read once at startup. Used in the User-Agent. */
export const SCANNER_VERSION: string = (
  JSON.parse(readFileSync(packageJsonPath, 'utf8')) as PackageJson
).version;
