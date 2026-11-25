import { writeFileSync } from 'node:fs';
import { CompactSign, exportJWK, generateKeyPair } from 'jose';
import { FIXTURE_TYPE } from '../src/authority-letter-profile.mjs';

const first = await generateKeyPair('ES256');
const second = await generateKeyPair('ES256');
const shape = async (key, kid) => ({ ...await exportJWK(key), kid, alg: 'ES256', use: 'sig', key_ops: ['verify'] });
const jwks = { keys: [await shape(first.publicKey, 'fixture-1'), await shape(second.publicKey, 'fixture-2')] };
const clock = '2026-11-25T12:00:00.000Z';
const manifest = {
  schema: 'einllc.agent-authority.v1', id: 'FAXTUREA', check: 'https://ein.llc/letter?n=FAXTUREA',
  issuer: { legalName: 'Fixture Company LLC', jurisdiction: 'Wyoming', entityType: 'LLC' }, companyProvenance: { kind: 'signer-stated' },
  signedBy: { name: 'Fixture Owner', title: 'Manager', at: clock },
  agent: { name: 'Fixture Agent', reference: 'https://example.test/agent', role: 'agent', isOwnerOrOfficer: false, maySign: false },
  may: ['quote'], limits: { currency: 'USD', perTransaction: 0, perMonth: null }, counterparties: 'any',
  needsPerson: ['contract', 'account'], validFrom: '2026-11-25', validUntil: '2026-12-25', grantsAccessToMoneyOrAccounts: false,
};
const baseHeader = { alg: 'ES256', typ: FIXTURE_TYPE, kid: 'fixture-1' };
const sign = async (value = manifest, header = {}, key = first.privateKey) => new CompactSign(Buffer.from(JSON.stringify(value)))
  .setProtectedHeader({ ...baseHeader, ...header }).sign(key);
const active = await sign();
const revoked = { ...manifest, id: 'FAXTURER', check: 'https://ein.llc/letter?n=FAXTURER' };
const [header, payload, signature] = active.split('.');
const encoded = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const response = (value, status) => ({ number: value.id, status, checkedAt: clock, startsOn: value.validFrom,
  expiresOn: value.validUntil, revokedAt: status === 'revoked' ? clock : null });
const fixed = {
  clock, jwks, activeStatus: response(manifest, 'active'), revokedStatus: response(revoked, 'revoked'),
  cases: [
    { name: 'valid-active', token: active, offline: 'offline' },
    { name: 'valid-revoked', token: await sign(revoked), offline: 'offline' },
    { name: 'rotation-new', token: await sign(manifest, { kid: 'fixture-2' }, second.privateKey), offline: 'offline' },
    { name: 'changed-payload', token: `${header}.${encoded({ ...manifest, may: ['order'] })}.${signature}`, offline: 'signature_invalid' },
    { name: 'wrong-key', token: await sign(manifest, {}, second.privateKey), offline: 'signature_invalid' },
    { name: 'unknown-kid', token: await sign(manifest, { kid: 'missing' }), offline: 'unknown_kid' },
    { name: 'wrong-type', token: await sign(manifest, { typ: 'other+jws' }), offline: 'invalid_profile' },
    { name: 'embedded-key', token: await sign(manifest, { jwk: jwks.keys[0] }), offline: 'invalid_profile' },
    { name: 'alternate-key-url', token: await sign(manifest, { jku: 'https://example.test/keys' }), offline: 'invalid_profile' },
    { name: 'alternate-certificate-url', token: await sign(manifest, { x5u: 'https://example.test/cert' }), offline: 'invalid_profile' },
    { name: 'wrong-algorithm', token: `${encoded({ ...baseHeader, alg: 'HS256' })}.${payload}.${signature}`, offline: 'invalid_profile' },
    { name: 'no-algorithm', token: `${encoded({ ...baseHeader, alg: 'none' })}.${payload}.`, offline: 'invalid_profile' },
    { name: 'duplicate-protected-field', token: `${Buffer.from('{"alg":"ES256",' + JSON.stringify(baseHeader).slice(1)).toString('base64url')}.${payload}.${signature}`, offline: 'invalid_profile' },
    { name: 'unknown-version', token: await sign({ ...manifest, schema: 'einllc.agent-authority.v2' }), offline: 'invalid_manifest' },
    { name: 'unknown-property', token: await sign({ ...manifest, issuer: { ...manifest.issuer, extra: true } }), offline: 'invalid_manifest' },
    { name: 'invalid-day', token: await sign({ ...manifest, validUntil: '2026-11-31' }), offline: 'invalid_manifest' },
    { name: 'unsafe-dollars', token: await sign({ ...manifest, limits: { ...manifest.limits, perTransaction: 9007199254740992 } }), offline: 'invalid_manifest' },
    { name: 'unsigned-payload', token: await sign({ ...manifest, signedBy: { ...manifest.signedBy, at: null } }), offline: 'invalid_manifest' },
    { name: 'keyed-check', token: await sign({ ...manifest, check: manifest.check + '#k=' + 'A'.repeat(22) }), offline: 'invalid_manifest' },
  ],
};
writeFileSync(new URL('../examples/vectors.json', import.meta.url), JSON.stringify(fixed, null, 2) + '\n');
writeFileSync(new URL('../examples/active.jws', import.meta.url), active + '\n');
writeFileSync(new URL('../examples/revoked.jws', import.meta.url), fixed.cases[1].token + '\n');
writeFileSync(new URL('../examples/jwks.json', import.meta.url), JSON.stringify(jwks, null, 2) + '\n');
