import { isIP } from 'node:net';
import tls from 'node:tls';
import type { LegacyProtocolProbe } from './types.js';

const PROBE_TIMEOUT_MS = 4000;

/**
 * Tries a handshake pinned to exactly one protocol version, to see whether
 * the server still accepts it. Resolves to true/false; never throws or
 * rejects, since a refused connection here just means "not accepted".
 *
 * ciphers: 'DEFAULT@SECLEVEL=0' is needed for the TLSv1/1.1 probes: modern
 * OpenSSL refuses those protocol versions at its default security level,
 * regardless of what the server supports, so without this every legacy
 * probe would fail locally even against a server that genuinely accepts
 * TLS 1.0/1.1.
 */
function probeVersion(
  ip: string,
  hostname: string,
  port: number,
  version: 'TLSv1' | 'TLSv1.1' | 'TLSv1.3',
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (accepted: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(accepted);
    };

    const socket = tls.connect({
      host: ip,
      port,
      ...(isIP(hostname) === 0 ? { servername: hostname } : {}),
      rejectUnauthorized: false,
      minVersion: version,
      maxVersion: version,
      ciphers: version === 'TLSv1.3' ? undefined : 'DEFAULT@SECLEVEL=0',
    });

    socket.setTimeout(PROBE_TIMEOUT_MS);
    socket.once('secureConnect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

/**
 * Probes a server for legacy TLS support (1.0, 1.1) and for TLS 1.3 support,
 * each as a separate, pinned handshake. Runs after the main connection has
 * already succeeded, so this is extra depth, not required for a scan to work.
 */
export async function probeLegacyProtocols(
  ip: string,
  hostname: string,
  port: number,
): Promise<LegacyProtocolProbe> {
  const [acceptsTls1, acceptsTls11, acceptsTls13] = await Promise.all([
    probeVersion(ip, hostname, port, 'TLSv1'),
    probeVersion(ip, hostname, port, 'TLSv1.1'),
    probeVersion(ip, hostname, port, 'TLSv1.3'),
  ]);

  const acceptedLegacyVersions: LegacyProtocolProbe['acceptedLegacyVersions'] = [];
  if (acceptsTls1) acceptedLegacyVersions.push('TLSv1');
  if (acceptsTls11) acceptedLegacyVersions.push('TLSv1.1');

  return { acceptedLegacyVersions, missingTls13: !acceptsTls13 };
}
