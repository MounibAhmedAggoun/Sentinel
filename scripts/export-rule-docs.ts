import { mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { RULE_CATALOG, RULE_DOC_CONTENT, renderRuleIndex, renderRulePage } from '@sentinel/scanner';

const outDir = path.resolve('docs', 'rules');

await mkdir(outDir, { recursive: true });

// Remove pages left over from rules that no longer have content.
const wanted = new Set<string>(['README.md']);
for (const entry of RULE_CATALOG) {
  if (RULE_DOC_CONTENT[entry.id] !== undefined) wanted.add(`${entry.id}.md`);
}
for (const file of await readdir(outDir)) {
  if (file.endsWith('.md') && !wanted.has(file)) await rm(path.join(outDir, file));
}

const documented = new Set<string>();
for (const entry of RULE_CATALOG) {
  const content = RULE_DOC_CONTENT[entry.id];
  if (content === undefined) continue;

  await writeFile(path.join(outDir, `${entry.id}.md`), renderRulePage(entry, content), 'utf8');
  documented.add(entry.id);
}

await writeFile(path.join(outDir, 'README.md'), renderRuleIndex(RULE_CATALOG, documented), 'utf8');

console.log(`wrote ${documented.size} rule pages to ${outDir}`);
