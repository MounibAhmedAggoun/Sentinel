#!/usr/bin/env node
import { Command } from 'commander';
import { resolveTarget } from '@sentinel/core';
import {
  DEFAULT_PORTS,
  evaluate,
  fetchHttp,
  parsePorts,
  resolveDns,
  scanPorts,
  scanTls,
} from '@sentinel/scanner';
import { ExitCode } from './exit-codes.js';
import { logger } from './logger.js';
import { targetSchema } from './validate.js';

const program = new Command();

program
  .name('sentinel')
  .description('Web security reconnaissance tool (authorized use only)')
  .version('0.0.0');

program
  .command('scan')
  .description('Scan an authorized target')
  .argument('<target>', 'hostname or IP address you are authorized to scan')
  .option('--ports <list>', 'comma-separated ports to check, e.g. 80,443')
  .option('--allow-private', 'allow private/internal addresses (local testing only)', false)
  .action(async (rawTarget: string, options: { ports?: string; allowPrivate: boolean }) => {
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
    const dns = await resolveDns(target);
    const http = await fetchHttp(`https://${target}/`, { allowPrivate });
    const httpPlain = await fetchHttp(`http://${target}/`, { allowPrivate });
    const tcp = await scanPorts(target, { ports, allowPrivate });
    const tls = await scanTls(target, { allowPrivate });

    const scan = { target, dns, http, httpPlain, tcp, tls };
    const findings = evaluate(scan);

    console.log(JSON.stringify({ ...scan, findings }, null, 2));

    // Informational findings are not problems, so only low and above count.
    const hasFindings = findings.some((finding) => finding.severity !== 'informational');
    process.exitCode = hasFindings ? ExitCode.Findings : ExitCode.Clean;
  });

await program.parseAsync();
