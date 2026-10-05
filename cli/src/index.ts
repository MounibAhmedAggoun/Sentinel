#!/usr/bin/env node
import { Command } from 'commander';
import { resolveTarget } from '@sentinel/core';
import { DEFAULT_PORTS, fetchHttp, parsePorts, resolveDns, scanPorts } from '@sentinel/scanner';
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

    const dns = await resolveDns(target);
    const http = await fetchHttp(`https://${target}/`, { allowPrivate: options.allowPrivate });
    const tcp = await scanPorts(target, { ports, allowPrivate: options.allowPrivate });
    console.log(JSON.stringify({ dns, http, tcp }, null, 2));

    process.exitCode = ExitCode.Clean;
  });

await program.parseAsync();
