import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

interface PackageJson {
  version: string;
}

const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url));

/** Read once at startup. The CLI always runs from its own package, so this never fails in practice. */
export const VERSION: string = (JSON.parse(readFileSync(packageJsonPath, 'utf8')) as PackageJson)
  .version;
