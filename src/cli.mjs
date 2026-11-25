#!/usr/bin/env node
import { open } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { TOKEN_LIMIT } from './authority-letter-profile.mjs';
import { createVerifier } from './verify.mjs';

async function readBounded(path, limit) {
  const file = await open(path);
  try {
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    return length <= limit ? buffer.subarray(0, length).toString('utf8') : null;
  } finally { await file.close(); }
}

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    origin: { type: 'string' }, jwks: { type: 'string' }, offline: { type: 'boolean' }, fixture: { type: 'boolean' },
    'allow-loopback': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
  } });
  if (values.help) {
    console.log('Usage: agent-authority-letter LETTER.jws [--origin https://ein.llc] [--jwks JWKS.json] [--offline] [--fixture] [--allow-loopback]');
    return 0;
  }
  if (positionals.length !== 1) throw new Error('supply exactly one letter file');
  const token = (await readBounded(positionals[0], TOKEN_LIMIT + 2) ?? '').replace(/\r?\n$/, '');
  const jwks = values.jwks ? JSON.parse(await readBounded(values.jwks, 65536) ?? '') : undefined;
  const result = await createVerifier({ ...values, jwks, allowLoopback: values['allow-loopback'] })(token);
  console.log(JSON.stringify(result));
  return result.signature !== 'valid' || result.schema !== 'valid' ? 1 : result.usable ? 0 : 3;
}

try { process.exitCode = await main(); }
catch { console.error('Invalid verifier inputs. See --help.'); process.exitCode = 2; }
