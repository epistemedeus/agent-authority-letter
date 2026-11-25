# EIN.LLC authority letter verifier

Verify the exact machine terms of a supplied EIN.LLC company letter using a service signature. Then check whether the letter is currently active. Verification requires a copy of the JWS and a trusted origin or pinned public keys. The owner who signed the company document remains identified by the `signedBy` field.

## Run the verifier

Use a copy of the compact JWS supplied by the letter holder. The verifier runs on Deno 2, Node 22.12+, and Python 3.11+.

### JavaScript from JSR

For a published `@epistemedeus/authority-letter` release, import its library in Deno:

```ts
import { createVerifier } from 'jsr:@epistemedeus/authority-letter@0.1.0';
```

Run the JSR CLI with Deno and grant access to the files and origin you supply:

```sh
deno run --allow-read=letter.jws --allow-net=ein.llc jsr:@epistemedeus/authority-letter@0.1.0/cli letter.jws --origin https://ein.llc
```

Deno 2.9 applies a 24-hour package age window by default. A brand-new release becomes available to default Deno installs after that window.

For Node ESM, add `@jsr:registry=https://npm.jsr.io` to the consumer project's `.npmrc`. Install the JSR package with `npm install @jsr/epistemedeus__authority-letter@0.1.0` and import `createVerifier` from `@jsr/epistemedeus__authority-letter`.

### Python from GitHub Releases

Install the wheel from its versioned release URL when the asset is available:

```sh
python -m pip install 'https://github.com/epistemedeus/agent-authority-letter/releases/download/v0.1.0/agent_authority_letter-0.1.0-py3-none-any.whl'
agent-authority-letter letter.jws --origin https://ein.llc
```

Both artifacts can also be installed from local files. A local npm tarball keeps the `agent-authority-letter` import and executable; a local wheel takes the same `pip install` command with a file path.

The CLIs return a JSON decision. Exit `0` means usable active authority. Exit `1` means integrity or schema could not be established. Exit `2` means invalid CLI inputs. Exit `3` means signature and schema passed and usable current authority was not established. Only `usable: true` promotes a result to current authority. Use `--offline --jwks /path/to/trusted-jwks.json` for local integrity. Offline `currentStatus` is always `unknown`.

```js
import { readFile } from 'node:fs/promises';
import { createVerifier } from '@jsr/epistemedeus__authority-letter';
const verify = createVerifier({ origin: 'https://ein.llc' });
const decision = await verify((await readFile('letter.jws', 'utf8')).trim());
console.log(decision.signature, decision.currentStatus, decision.usable);
```

```python
from pathlib import Path
from agent_authority_letter import Verifier
verify = Verifier(origin='https://ein.llc')
decision = verify.verify(Path('letter.jws').read_text().strip())
print(decision['signature'], decision['currentStatus'], decision['usable'])
```

## Wire contract

- The versioned Draft 2020-12 [schema](src/einllc.agent-authority.v1.schema.json) is served at `/schemas/einllc.agent-authority.v1.schema.json`. It describes the immutable company terms. `signedBy.at` can be null in an unsigned legacy manifest. A verifiable service copy requires the original owner signing time and a fragment-free check link.
- `GET /api/letters/{number}` returns fresh status and dates. With the correct `X-Letter-Key`, the response also includes the immutable original and, when available, `signedCopy: {"format":"compact-jws","jws":"…"}`. MCP `check_authority_letter` uses the same header and adds the same signed copy. Once supplied the JWS, the recipient needs only the public verifier inputs.
- The compact attached JWS has protected `alg: ES256`, `typ: einllc.agent-authority.v1+jws`, and the signing key's `kid`. The origin publishes strictly public P-256 verification keys at `/.well-known/jwks.json`. The verifier reads status from that same caller-pinned origin and matches number, validity, and recency. The validity end date is inclusive in UTC. An unavailable, stale, or mismatched reply yields `unknown`.
- Status is requested on every verification, with a five-second timeout and no redirects. The key cache retains a JWKS for up to five minutes and refreshes for unknown keys at most once per 30 seconds. Publish a new public key before activation and keep previous public keys available for previously supplied copies.

## Examples

`examples/active.jws`, `examples/revoked.jws`, and `examples/jwks.json` are fixed-clock synthetic vectors. Select `--fixture` explicitly. Fixture results always have `usable: false`. `examples/vectors.json` also includes changed payloads, header and algorithm refusals, and invalid manifest cases.

```sh
agent-authority-letter examples/active.jws --offline --fixture --jwks examples/jwks.json
```

The service's `/api/letters/examples.json` returns illustrative `active` and `revoked` manifest/status pairs with a rolling UTC validity period for display. This endpoint is separate from production letter lookup and its examples carry `fixture: true`. Fixed vectors are for signature demonstrations. The verifier's optional online fixture mode uses a caller-run simulator at `/fixtures/api/letters/{number}`. `--allow-loopback` permits HTTP only on a named loopback origin for local tests.

## Test

Run `npm ci && npm test`. To exercise the same cases in Python, install the Python project into a virtual environment, set `AUTHORITY_TEST_PYTHON` to its Python executable, and repeat `npm test`.

To validate the JSR package with Deno 2.9.8, install the Node 22 type declarations for the publish-time checker and run the checked dry run:

```sh
deno install --node-modules-dir=auto --no-lock --no-save npm:@types/node@22.20.5
deno publish --dry-run --node-modules-dir=auto --no-lock
```

To build the Python wheel and source distribution from a clean checkout, run `python -m build`.
