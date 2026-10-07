import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { reportJsonSchema } from '@sentinel/scanner';

const out = path.resolve('docs', 'report.schema.json');

await mkdir(path.dirname(out), { recursive: true });
await writeFile(out, `${JSON.stringify(reportJsonSchema(), null, 2)}\n`, 'utf8');

console.log(`wrote ${out}`);
