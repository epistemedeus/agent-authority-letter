import { strict as assert } from 'node:assert';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import { createVerifier } from '../src/verify.mjs';
import { TOKEN_LIMIT } from '../src/authority-letter-profile.mjs';

const vectors = JSON.parse(readFileSync(new URL('../examples/vectors.json', import.meta.url)));
const run = promisify(execFile);
const initial = Date.parse(vectors.clock);
const [oldKey, nextKey] = vectors.jwks.keys;
const [old, revoked, next] = vectors.cases.map(({ token }) => token);
const python = process.env.AUTHORITY_TEST_PYTHON;
const foreign = async (input) => {
  if (!python) return undefined;
  const code = `import json, sys\nfrom agent_authority_letter import Verifier\np = json.loads(sys.argv[1])\nv = Verifier(**p['options'], clock=lambda:p['clock']/1000)\nprint(json.dumps([v.verify(t) for t in p['tokens']]))`;
  return JSON.parse((await run(python, ['-c', code, JSON.stringify(input)], { env: { ...process.env, PYTHONPATH: 'python' } })).stdout);
};

test('shared offline fixtures, size bound, mode separation and strictly public unique keys', async () => {
  const { jwks, cases } = vectors;
  const opts = { offline: true, fixture: true, jwks };
  const verify = createVerifier(opts);
  const received = await Promise.all([...cases.map(({ token }) => token), 'A'.repeat(TOKEN_LIMIT + 1)].map(verify));
  assert.deepEqual(received.map(value => value.reason), [...cases.map(item => item.offline), 'invalid_profile']);
  assert(received.every(row => !row.usable && row.currentStatus === 'unknown'));
  assert.equal((await createVerifier({ offline: true, jwks })(old)).reason, 'invalid_profile');
  for (const keys of [[oldKey, oldKey], [{ ...oldKey, crv: 'P-384' }], [{ ...oldKey, d: oldKey.x }], [{ kty: 'oct', k: oldKey.x }]]) {
    assert.throws(() => createVerifier({ offline: true, jwks: { keys } }), /invalid_jwks/);
  }
  if (python) assert.deepEqual(await foreign({ options: opts, clock: initial, tokens: [...cases.map(({ token }) => token), 'A'.repeat(TOKEN_LIMIT + 1)] }), received);
});

test('live status is fresh, matched, independently checked and observes key rotation', async (t) => {
  let now = initial, keys = [oldKey], keyReads = 0, change;
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/.well-known/jwks.json') { keyReads++; return res.end(JSON.stringify({ keys })); }
    assert.match(req.url, /^\/fixtures\/api\/letters\/FAXTURE[AR]$/);
    res.setHeader('cache-control', 'no-store');
    if (change === 'outage') { res.statusCode = 503; return res.end('{}'); }
    if (change === 'redirect') { res.writeHead(302, { Location: 'https://example.test/redirect' }); return res.end('{}'); }
    if (change === 'age') res.setHeader('age', '10');
    const base = req.url.endsWith('R') ? vectors.revokedStatus : vectors.activeStatus;
    res.end(JSON.stringify({ ...base, checkedAt: new Date(now).toISOString(), ...change }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const origin = 'http://127.0.0.1:' + server.address().port;
  const make = () => createVerifier({ origin, allowLoopback: true, fixture: true, clock: () => now });
  const verify = make();
  assert.equal((await verify(old)).currentStatus, 'active');
  assert.equal((await verify(revoked)).currentStatus, 'revoked');
  keys = [oldKey, nextKey];
  assert.equal((await verify(next)).reason, 'unknown_kid');
  assert.equal(keyReads, 1);
  now += 30000;
  assert.equal((await verify(next)).currentStatus, 'active');
  assert.equal((await verify(old)).currentStatus, 'active');
  assert.equal(keyReads, 2);
  assert.equal((await make()(next)).currentStatus, 'active');
  assert.equal(keyReads, 3);
  if (python) {
    const values = await foreign({ options: { origin, allow_loopback: true, fixture: true }, clock: now, tokens: [old, revoked, next] });
    assert.deepEqual(values, await Promise.all([old, revoked, next].map(verify)));
  }
  const scenarios = [
    [initial, { number: 'FAXTURER' }, 'unknown'], [initial, { expiresOn: '2027-12-25' }, 'unknown'],
    [initial, { checkedAt: '2026-11-25T11:58:59.000Z' }, 'unknown'], [initial, { checkedAt: '2026-11-25T12:00:06.000Z' }, 'unknown'],
    [initial, { status: 'replaced' }, 'replaced'], [initial, { status: 'other' }, 'unknown'],
    [initial, 'outage', 'unknown'], [initial, 'redirect', 'unknown'], [initial, 'age', 'unknown'],
    [Date.parse('2026-11-24T23:59:59.999Z'), { status: 'pending' }, 'pending'],
    [Date.parse('2026-12-25T23:59:59.999Z'), {}, 'active'],
    [Date.parse('2026-12-26T00:00:00.000Z'), { status: 'expired' }, 'expired'],
  ];
  for (const [instant, mutation, expected] of scenarios) {
    now = instant;
    change = mutation;
    const output = await make()(old);
    assert.equal(output.currentStatus, expected);
    assert.equal(output.signature, 'valid');
    assert.equal(output.usable, false);
    if (python) {
      const [other] = await foreign({ options: { origin, allow_loopback: true, fixture: true }, clock: now, tokens: [old] });
      assert.deepEqual(other, output);
    }
  }
});
