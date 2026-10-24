export const ExitCode = {
  Clean: 0,
  Findings: 1,
  Usage: 2,
  ScanError: 3,
} as const;

export interface ExitDecisionInput {
  /** Number of scan modules that ran (dns, http, httpPlain, tcp, tls = 5). */
  modulesRun: number;
  /** Number of those modules that ended in an error. */
  modulesFailed: number;
  /** True if any finding is low severity or higher (not just informational). */
  hasFindings: boolean;
}

/**
 * Decides the CLI's exit code for a completed scan. Pure, so it's easy to test
 * every combination without running a real scan.
 */
export function decideExitCode(input: ExitDecisionInput): (typeof ExitCode)[keyof typeof ExitCode] {
  const { modulesRun, modulesFailed, hasFindings } = input;

  if (modulesRun > 0 && modulesFailed >= modulesRun) return ExitCode.ScanError;
  if (hasFindings) return ExitCode.Findings;
  return ExitCode.Clean;
}
