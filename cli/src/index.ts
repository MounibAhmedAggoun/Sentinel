#!/usr/bin/env node
import { Command } from 'commander';
import { ExitCode } from './exit-codes.js';
import { logger } from './logger.js';

const program = new Command();

program
  .name('sentinel')
  .description('Web security reconnaissance tool (authorized use only)')
  .version('0.0.0');

program
  .command('scan')
  .description('Scan an authorized target')
  .argument('<target>', 'hostname or IP address you are authorized to scan')
  .option('--allow-private', 'allow private/internal addresses (local testing only)', false)
  .action((target: string, options: { allowPrivate: boolean }) => {
    logger.info({ target, allowPrivate: options.allowPrivate }, 'scan requested');
    process.exitCode = ExitCode.Clean;
  });

program.parse();
