"""Verify attached authority-letter JWS and read independent current status."""

import json
import re
import time
from datetime import UTC, date, datetime, timedelta
from importlib.resources import files
from threading import Lock
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlsplit

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.util import urlsafe_b64decode
from joserfc.jwk import ECKey
from jsonschema import Draft202012Validator, FormatChecker

TOKEN_LIMIT = 24576
JWKS_PATH = '/.well-known/jwks.json'
LETTER_TYPE = 'einllc.agent-authority.v1+jws'
FIXTURE_TYPE = 'einllc.agent-authority.v1+fixture-jws'
KID = re.compile(r'[A-Za-z0-9._-]{1,128}')
COORDINATE = re.compile(r'[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]')
TOKEN = re.compile(r'[A-Za-z0-9_-]{1,1024}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}')
RESPONSE_LIMIT = 65536
SCHEMA = json.loads(files(__package__).joinpath('einllc.agent-authority.v1.schema.json').read_bytes())
FORMATS = FormatChecker()


@FORMATS.checks('date', raises=ValueError)
def valid_day(value):
    return isinstance(value, str) and date.fromisoformat(value).isoformat() == value


@FORMATS.checks('date-time', raises=ValueError)
def valid_instant(value):
    return isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', value) is not None and date.fromisoformat(value[:10]) is not None and datetime.fromisoformat(value) is not None


@FORMATS.checks('uri', raises=ValueError)
def valid_uri(value):
    return isinstance(value, str) and bool(urlsplit(value).scheme and urlsplit(value).netloc)


VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FORMATS)


def _valid_manifest(value):
    if not VALIDATOR.is_valid(value) or not value['signedBy']['at'] or value['check'] != 'https://ein.llc/letter?n=' + value['id']:
        return False
    if not value['agent']['name'].strip() or not value['agent']['reference'].strip() or not value['may']:
        return False
    start = date.fromisoformat(value['validFrom'])
    end = date.fromisoformat(value['validUntil'])
    if end < start:
        return False
    if start.year == 9999:
        return True
    month, day = (3, 1) if (start.month, start.day) == (2, 29) else (start.month, start.day)
    return end <= date(start.year + 1, month, day) - timedelta(days=1)


def _public_jwks(value):
    fields = {'kty', 'crv', 'x', 'y', 'kid', 'alg', 'use', 'key_ops'}
    if not isinstance(value, dict) or set(value) != {'keys'} or not isinstance(value['keys'], list) or not 1 <= len(value['keys']) <= 32:
        raise ValueError('invalid_jwks')
    keys = {}
    for key in value['keys']:
        if (not isinstance(key, dict) or set(key) != fields or key['kty'] != 'EC' or key['crv'] != 'P-256'
                or key['alg'] != 'ES256' or key['use'] != 'sig' or key['key_ops'] != ['verify']
                or not isinstance(key['kid'], str) or not KID.fullmatch(key['kid']) or key['kid'] in keys
                or not all(isinstance(key[field], str) and COORDINATE.fullmatch(key[field]) for field in ('x', 'y'))):
            raise ValueError('invalid_jwks')
        keys[key['kid']] = {**key, 'key_ops': ['verify']}
    return keys


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_json(url, status):
    request = Request(url, headers={'Accept': 'application/json', 'Cache-Control': 'no-cache'})
    deadline = time.monotonic() + 5
    with build_opener(_NoRedirect()).open(request, timeout=5) as response:
        headers = response.headers
        if (response.status < 200 or response.status >= 300 or 'Content-Type' not in headers or headers.get_content_type() != 'application/json'
                or int(headers.get('Content-Length', '0')) > RESPONSE_LIMIT
                or (status and (not re.search(r'\bno-store\b', headers.get('Cache-Control', ''), flags=re.I) or int(headers.get('Age', '0')) > 0))):
            raise ValueError('unusable_response')
        data = bytearray()
        while time.monotonic() < deadline:
            chunk = response.read1(min(8192, RESPONSE_LIMIT + 1 - len(data)))
            if not chunk:
                return _json(data)
            data.extend(chunk)
            if len(data) > RESPONSE_LIMIT:
                break
    raise ValueError('unusable_response')


def _origin(value, allow_loopback):
    if not isinstance(value, str) or re.search(r'[\x00-\x20\\?#]', value):
        raise ValueError('invalid_origin')
    url = urlsplit(value)
    loopback = url.hostname in ('localhost', '127.0.0.1', '::1')
    if (not url.hostname or url.username is not None or url.password is not None or url.path not in ('', '/')
            or not (url.scheme == 'https' or (url.scheme == 'http' and loopback and allow_loopback))):
        raise ValueError('invalid_origin')
    return f'{url.scheme}://{url.netloc}'


def _json(data):
    def invalid_constant(_):
        raise ValueError('invalid_json')
    return json.loads(data.decode('utf-8'), parse_constant=invalid_constant)


def _status(value, manifest, now):
    if not isinstance(value, dict):
        return 'unknown'
    state = value.get('status')
    if (value.get('number') != manifest['id'] or value.get('startsOn') != manifest['validFrom']
            or value.get('expiresOn') != manifest['validUntil'] or state not in ('active', 'pending', 'expired', 'revoked', 'replaced')
            or not valid_instant(value.get('checkedAt')) or 'revokedAt' not in value
            or (not valid_instant(value['revokedAt']) if state == 'revoked' else value['revokedAt'] is not None)):
        return 'unknown'
    age = now - datetime.fromisoformat(value['checkedAt']).timestamp()
    if age > 60 or age < -5:
        return 'unknown'
    if state in ('revoked', 'replaced'):
        return state
    today = datetime.fromtimestamp(now, UTC).date().isoformat()
    expected = 'pending' if today < manifest['validFrom'] else 'expired' if today > manifest['validUntil'] else 'active'
    return state if state == expected else 'unknown'


class Verifier:
    """Pin an origin for current status. Offline verification also pins public keys."""

    def __init__(self, *, origin=None, jwks=None, offline=False, fixture=False, allow_loopback=False, clock=time.time):
        if (not offline and not origin) or (offline and jwks is None):
            raise ValueError('trusted_key_source_required')
        self.origin = None if origin is None else _origin(origin, allow_loopback)
        self.pinned = None if jwks is None else _public_jwks(jwks)
        self.offline, self.fixture, self.clock = offline, fixture, clock
        self._keys = {}
        self._cached_at = self._attempted_at = float('-inf')
        self._lock = Lock()

    def _key(self, kid):
        if self.pinned is not None:
            return self.pinned.get(kid)
        with self._lock:
            now = self.clock()
            if now - self._cached_at < 300 and (kid in self._keys or now - self._attempted_at < 30):
                return self._keys.get(kid)
            if now - self._attempted_at >= 30:
                self._attempted_at = now
                self._keys = _public_jwks(_read_json(self.origin + JWKS_PATH, False))
                self._cached_at = self.clock()
            if self.clock() - self._cached_at >= 300:
                raise ValueError('keys_unavailable')
            return self._keys.get(kid)

    def verify(self, token):
        result = {'signature': 'invalid', 'schema': 'unknown', 'currentStatus': 'unknown', 'usable': False, 'fixture': self.fixture}
        if not isinstance(token, str) or len(token) > TOKEN_LIMIT or not TOKEN.fullmatch(token):
            return {**result, 'reason': 'invalid_profile'}
        try:
            # This library parses the wire format. The profile independently rejects
            # unexpected and duplicate protected fields before key selection.
            protected = urlsafe_b64decode(token.split('.', 1)[0].encode('ascii')).decode('utf-8')
            header = json.loads(protected)
            if (not isinstance(header, dict) or set(header) != {'alg', 'typ', 'kid'}
                    or len(re.findall(r'"(?:alg|typ|kid)"\s*:', protected)) != 3
                    or header['alg'] != 'ES256' or header['typ'] != (FIXTURE_TYPE if self.fixture else LETTER_TYPE)
                    or not isinstance(header['kid'], str) or not KID.fullmatch(header['kid'])):
                raise ValueError('invalid_header')
        except (ValueError, TypeError):
            return {**result, 'reason': 'invalid_profile'}
        try:
            key = self._key(header['kid'])
        except (OSError, ValueError, TypeError):
            return {**result, 'signature': 'unknown', 'reason': 'keys_unavailable'}
        if key is None:
            return {**result, 'reason': 'unknown_kid'}
        try:
            verified = jws.deserialize_compact(token, ECKey.import_key(key), algorithms=['ES256'])
        except (JoseError, ValueError, TypeError):
            return {**result, 'reason': 'signature_invalid'}
        result['signature'] = 'valid'
        try:
            manifest = _json(verified.payload)
            if not _valid_manifest(manifest):
                raise ValueError('invalid_manifest')
        except (ValueError, TypeError, RecursionError):
            return {**result, 'schema': 'invalid', 'reason': 'invalid_manifest'}
        result['schema'] = 'valid'
        if self.offline:
            return {**result, 'reason': 'offline', 'manifest': manifest}
        try:
            path = '/fixtures/api/letters/' if self.fixture else '/api/letters/'
            result['currentStatus'] = _status(_read_json(self.origin + path + manifest['id'], True), manifest, self.clock())
        except (OSError, ValueError, TypeError, RecursionError):
            pass  # Integrity remains independently available.
        result['usable'] = result['currentStatus'] == 'active' and not self.fixture
        return {**result, 'reason': 'status_unknown' if result['currentStatus'] == 'unknown' else result['currentStatus'], 'manifest': manifest}
