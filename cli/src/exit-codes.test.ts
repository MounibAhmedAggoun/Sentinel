import { describe, expect, it } from 'vitest';
import { decideExitCode, ExitCode } from './exit-codes.js';

describe('decideExitCode', () => {
  it('is Clean when everything worked and there are no findings', () => {
    expect(decideExitCode({ modulesRun: 5, modulesFailed: 0, hasFindings: false })).toBe(
      ExitCode.Clean,
    );
  });

  it('is Findings when something worked and findings exist', () => {
    expect(decideExitCode({ modulesRun: 5, modulesFailed: 0, hasFindings: true })).toBe(
      ExitCode.Findings,
    );
  });

  it('is ScanError when every module failed, even with findings', () => {
    expect(decideExitCode({ modulesRun: 5, modulesFailed: 5, hasFindings: true })).toBe(
      ExitCode.ScanError,
    );
  });

  it('is ScanError when every module failed and there are no findings', () => {
    expect(decideExitCode({ modulesRun: 5, modulesFailed: 5, hasFindings: false })).toBe(
      ExitCode.ScanError,
    );
  });

  it('is Findings (not ScanError) when only some modules failed', () => {
    expect(decideExitCode({ modulesRun: 5, modulesFailed: 4, hasFindings: true })).toBe(
      ExitCode.Findings,
    );
  });

  it('is Clean (not ScanError) when only some modules failed and no findings', () => {
    expect(decideExitCode({ modulesRun: 5, modulesFailed: 4, hasFindings: false })).toBe(
      ExitCode.Clean,
    );
  });

  it('is not ScanError when no modules ran at all', () => {
    // Guards the modulesRun > 0 check: 0 >= 0 would otherwise look like "all failed".
    expect(decideExitCode({ modulesRun: 0, modulesFailed: 0, hasFindings: false })).toBe(
      ExitCode.Clean,
    );
  });
});
