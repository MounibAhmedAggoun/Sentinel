/** Shared types and finding rules live here. */
export const SENTINEL_NAME = 'sentinel';

export type Severity = 'informational' | 'low' | 'medium' | 'high';

export { checkIp, type IpCheck } from './net-guard.js';
export { resolveTarget, type ResolveResult } from './resolve-target.js';
