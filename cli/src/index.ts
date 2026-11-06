#!/usr/bin/env node
import { Command } from 'commander';
import { resolveTarget, type ResolveResult } from '@sentinel/core';
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
import { parseConcurrency } from './concurrency.js';
import {
  createDeadline,
  DeadlineError,
  DEFAULT_MAX_DURATION_SECONDS,
  parseMaxDuration,
} from './deadline.js';
import { decideExitCode, ExitCode } from './exit-codes.js';
import { formatTerminal, sanitize } from './format.js';
import { logger } from './logger.js';
import { countFailedModules } from './module-failures.js';
import { parseTimeout } from './timeout.js';
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
  .option(
    '--probe-legacy-tls',
    'also probe for outdated TLS versions (a few extra handshakes)',
    false,
  )
  .option(
    '--max-duration <seconds>',
    'stop the scan if it runs longer than this (1 to 3600)',
    String(DEFAULT_MAX_DURATION_SECONDS),
  )
  .option(
    '--timeout <seconds>',
    'time limit for each HTTP request, TCP connection and TLS handshake (1 to 60)',
  )
  .option('--concurrency <number>', 'how many TCP port checks run at once (1 to 20, default 5)')
  .action(
    async (
      rawTarget: string,
      options: {
        ports?: string;
        json?: string;
        allowPrivate: boolean;
        probeLegacyTls: boolean;
        maxDuration: string;
        timeout?: string;
        concurrency?: string;
      },
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

        const duration = parseMaxDuration(options.maxDuration);
        if (!duration.ok) {
          logger.error({ reason: duration.error }, 'invalid max duration');
          process.exitCode = ExitCode.Usage;
          return;
        }

        // Without --timeout, each module keeps its own default.
        let timeoutOption: { timeoutMs?: number } = {};
        if (options.timeout !== undefined) {
          const timeout = parseTimeout(options.timeout);
          if (!timeout.ok) {
            logger.error({ reason: timeout.error }, 'invalid timeout');
            process.exitCode = ExitCode.Usage;
            return;
          }
          timeoutOption = { timeoutMs: timeout.ms };
        }

        // Without --concurrency, the TCP module keeps its own default.
        let concurrencyOption: { concurrency?: number } = {};
        if (options.concurrency !== undefined) {
          const concurrency = parseConcurrency(options.concurrency);
          if (!concurrency.ok) {
            logger.error({ reason: concurrency.error }, 'invalid concurrency');
            process.exitCode = ExitCode.Usage;
            return;
          }
          concurrencyOption = { concurrency: concurrency.value };
        }

        logger.info({ target }, 'scan requested');

        // One clock for the whole scan. A step that runs past it, or a step that
        // would start after it, stops the scan.
        const withDeadline = createDeadline(duration.ms);

        const result = await withDeadline(() =>
          resolveTarget(target, { allowPrivate: options.allowPrivate }),
        );
        if (!result.allowed) {
          logger.error({ target, reason: result.reason }, 'target rejected');
          process.exitCode = ExitCode.Usage;
          return;
        }
        logger.info({ target, ips: result.ips }, 'target validated');

        const allowPrivate = options.allowPrivate;
        const startedAt = new Date();

        // Resolve once: every module reuses the IPs validated above.
        // Other hosts (e.g. redirect targets) are still resolved and checked fresh.
        const resolveOnce = (
          host: string,
          opts: { allowPrivate: boolean },
        ): Promise<ResolveResult> =>
          host.toLowerCase() === target.toLowerCase()
            ? Promise.resolve(result)
            : resolveTarget(host, opts);

        const dns = await withDeadline(() => resolveDns(target));
        const http = await withDeadline(() =>
          fetchHttp(`https://${target}/`, { allowPrivate, resolve: resolveOnce, ...timeoutOption }),
        );
        const httpPlain = await withDeadline(() =>
          fetchHttp(`http://${target}/`, { allowPrivate, resolve: resolveOnce, ...timeoutOption }),
        );
        const tcp = await withDeadline(() =>
          scanPorts(target, {
            ports,
            allowPrivate,
            resolve: resolveOnce,
            ...timeoutOption,
            ...concurrencyOption,
          }),
        );
        const tls = await withDeadline(() =>
          scanTls(target, {
            allowPrivate,
            probeLegacy: options.probeLegacyTls,
            resolve: resolveOnce,
            ...timeoutOption,
          }),
        );

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
        if (err instanceof DeadlineError) {
          logger.error(
            { maxDurationSeconds: Number(options.maxDuration) },
            'scan stopped: it exceeded the maximum duration',
          );
        } else {
          logger.error(
            { reason: err instanceof Error ? err.message : 'unknown error' },
            'scan failed unexpectedly',
          );
        }
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
