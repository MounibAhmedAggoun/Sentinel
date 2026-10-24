#!/usr/bin/env node
import { Command } from 'commander';
import { resolveTarget } from '@sentinel/core';
import {
  buildReport,
  DEFAULT_PORTS,
  evaluate,
  fetchHttp,
  parsePorts,
  resolveDns,
  scanPorts,
  scanTls,
  writeReport,
} from '@sentinel/scanner';
import { decideExitCode, ExitCode } from './exit-codes.js';
import { formatTerminal, sanitize } from './format.js';
import { logger } from './logger.js';
import { countFailedModules } from './module-failures.js';
import { targetSchema } from './validate.js';
import { validateReportFile } from './validate-report.js';

import { VERSION } from './version.js';

const program = new Command();

program
  .name('sentinel')
  .description('Web security reconnaissance tool (authorized use only)')
  .version(VERSION);

program
  .command('scan')
  .description('Scan an authorized target')
  .argument('<target>', 'hostname or IP address you are authorized to scan')
  .option('--ports <list>', 'comma-separated ports to check, e.g. 80,443')
  .option('--json <file>', 'also write the full report to this JSON file')
  .option('--allow-private', 'allow private/internal addresses (local testing only)', false)
  .action(
    async (
      rawTarget: string,
      options: { ports?: string; json?: string; allowPrivate: boolean },
    ) => {
      try {
        const parsed = targetSchema.safeParse(rawTarget);
        if (!parsed.success) {
          logger.error({ reason: parsed.error.issues[0]?.message }, 'invalid target');
          process.exitCode = ExitCode.Usage;
          return;
        }
        const target = parsed.data;

        let ports: number[] = [...DEFAULT_PORTS];
        if (options.ports !== undefined) {
          const parsedPorts = parsePorts(options.ports);
          if (!parsedPorts.ok) {
            logger.error({ reason: parsedPorts.error }, 'invalid ports');
            process.exitCode = ExitCode.Usage;
            return;
          }
          ports = parsedPorts.ports;
        }

        logger.info({ target }, 'scan requested');

        const result = await resolveTarget(target, { allowPrivate: options.allowPrivate });
        if (!result.allowed) {
          logger.error({ target, reason: result.reason }, 'target rejected');
          process.exitCode = ExitCode.Usage;
          return;
        }
        logger.info({ target, ips: result.ips }, 'target validated');

        const allowPrivate = options.allowPrivate;
        const startedAt = new Date();

        const dns = await resolveDns(target);
        const http = await fetchHttp(`https://${target}/`, { allowPrivate });
        const httpPlain = await fetchHttp(`http://${target}/`, { allowPrivate });
        const tcp = await scanPorts(target, { ports, allowPrivate });
        const tls = await scanTls(target, { allowPrivate });

        const scan = { target, dns, http, httpPlain, tcp, tls };
        const findings = evaluate(scan);

        const report = buildReport({
          scan,
          findings,
          startedAt,
          finishedAt: new Date(),
          toolVersion: VERSION,
        });

        if (options.json !== undefined) {
          try {
            await writeReport(report, options.json);
            logger.info({ file: options.json }, 'report written');
          } catch (err) {
            logger.error(
              {
                file: options.json,
                reason: err instanceof Error ? err.message : 'unknown error',
              },
              'could not write report',
            );
            process.exitCode = ExitCode.ScanError;
            return;
          }
        }

        console.log(formatTerminal(report));

        process.exitCode = decideExitCode({
          modulesRun: 5,
          modulesFailed: countFailedModules(scan),
          hasFindings: findings.some((finding) => finding.severity !== 'informational'),
        });
      } catch (err) {
        logger.error(
          { reason: err instanceof Error ? err.message : 'unknown error' },
          'scan failed unexpectedly',
        );
        process.exitCode = ExitCode.ScanError;
      }
    },
  );

program
  .command('validate')
  .description('Check that a file is a valid Sentinel report')
  .argument('<file>', 'path to a JSON report')
  .action(async (file: string) => {
    const outcome = await validateReportFile(file);
    if (!outcome.ok) {
      console.error(`Invalid report: ${sanitize(outcome.error)}`);
      process.exitCode = ExitCode.Usage;
      return;
    }

    const { report } = outcome;
    console.log(
      `Valid Sentinel report (schema ${report.schemaVersion}) for ${sanitize(report.target)}: ` +
        `${report.findings.length} finding(s), ${report.errors.length} check error(s).`,
    );
    process.exitCode = ExitCode.Clean;
  });

await program.parseAsync();
