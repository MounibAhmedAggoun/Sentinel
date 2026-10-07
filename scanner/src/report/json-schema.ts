import { z } from 'zod';
import { reportSchema } from './schema.js';

/** The report format as a standard JSON Schema document, for other tools to validate against. */
export function reportJsonSchema(): Record<string, unknown> {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'Sentinel scan report',
    ...z.toJSONSchema(reportSchema),
  };
}
