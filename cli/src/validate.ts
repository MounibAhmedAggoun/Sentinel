import { isIP } from 'node:net';
import { z } from 'zod';

const HOSTNAME =
  /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

function isValidTarget(value: string): boolean {
  if (isIP(value) !== 0) return true;
  if (!HOSTNAME.test(value)) return false;
  // The last label (TLD) must start with a letter. This rejects numeric tricks
  // like "2130706433" or "0x7f000001" that some resolvers read as IP addresses.
  const lastLabel = value.split('.').pop() ?? '';
  return /^[a-z]/i.test(lastLabel);
}

export const targetSchema = z
  .string()
  .trim()
  .min(1, 'target is required')
  .max(253, 'target is too long')
  .refine(isValidTarget, { message: 'must be a valid hostname or IP address' });
