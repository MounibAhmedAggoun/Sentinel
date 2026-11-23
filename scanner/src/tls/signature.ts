/** One DER element: its tag, and where its content starts and ends in the buffer. */
interface Tlv {
  tag: number;
  start: number;
  end: number;
}

/** Reads one DER element at `offset`. Returns null when the bytes are not well-formed. */
function readTlv(buf: Buffer, offset: number): Tlv | null {
  const tag = buf[offset];
  const first = buf[offset + 1];
  if (tag === undefined || first === undefined) return null;

  let length: number;
  let start: number;
  if (first < 0x80) {
    length = first;
    start = offset + 2;
  } else {
    const count = first & 0x7f;
    // Indefinite length is not DER, and more than 4 length bytes is not a certificate.
    if (count < 1 || count > 4) return null;
    length = 0;
    for (let i = 0; i < count; i++) {
      const byte = buf[offset + 2 + i];
      if (byte === undefined) return null;
      length = length * 256 + byte;
    }
    start = offset + 2 + count;
  }

  const end = start + length;
  if (end > buf.length) return null;
  return { tag, start, end };
}

/** Turns the bytes of an OBJECT IDENTIFIER into dotted text such as "1.2.840.113549.1.1.11". */
function decodeOid(bytes: Buffer): string | null {
  const first = bytes[0];
  if (first === undefined) return null;
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte === undefined) return null;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** Names in the style Node uses, for the signature algorithms seen in real certificates. */
const KNOWN_ALGORITHMS: Record<string, string> = {
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'ED25519',
  '1.3.101.113': 'ED448',
};

/**
 * Reads the signature algorithm from the raw DER bytes of a certificate. Node only
 * offers this from v24.9.0, and Sentinel supports older versions too.
 * A certificate is SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
 * An algorithm that is not in the list above is returned as its dotted OID.
 * Returns null when the bytes are not a well-formed certificate.
 */
export function readSignatureAlgorithm(raw: Buffer): string | null {
  const certificate = readTlv(raw, 0);
  if (certificate === null || certificate.tag !== 0x30) return null;

  const tbs = readTlv(raw, certificate.start);
  if (tbs === null || tbs.tag !== 0x30) return null;

  const algorithm = readTlv(raw, tbs.end);
  if (algorithm === null || algorithm.tag !== 0x30 || algorithm.end > certificate.end) return null;

  const oid = readTlv(raw, algorithm.start);
  if (oid === null || oid.tag !== 0x06 || oid.end > algorithm.end) return null;

  const dotted = decodeOid(raw.subarray(oid.start, oid.end));
  if (dotted === null) return null;
  return KNOWN_ALGORITHMS[dotted] ?? dotted;
}
