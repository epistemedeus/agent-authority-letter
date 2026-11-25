import argparse
import json
import re
import sys
from pathlib import Path

from . import RESPONSE_LIMIT, TOKEN_LIMIT, Verifier


def main():
    parser = argparse.ArgumentParser(description='Verify an authority letter and independently check current status.')
    parser.add_argument('letter', type=Path)
    parser.add_argument('--origin')
    parser.add_argument('--jwks', type=Path)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--allow-loopback', action='store_true')
    args = parser.parse_args()
    try:
        with args.letter.open('rb') as file:
            data = file.read(TOKEN_LIMIT + 3)
        token = '' if len(data) >= TOKEN_LIMIT + 3 else re.sub(r'\r?\n\Z', '', data.decode('utf-8'))
        jwks = None
        if args.jwks:
            with args.jwks.open('rb') as file:
                data = file.read(RESPONSE_LIMIT + 1)
            if len(data) > RESPONSE_LIMIT:
                raise ValueError('invalid_jwks')
            jwks = json.loads(data)
        result = Verifier(origin=args.origin, jwks=jwks, offline=args.offline, fixture=args.fixture, allow_loopback=args.allow_loopback).verify(token)
    except (ValueError, OSError, TypeError, RecursionError):
        print('Invalid verifier inputs. See --help.', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, separators=(',', ':')))
    return 1 if result['signature'] != 'valid' or result['schema'] != 'valid' else 0 if result['usable'] else 3


if __name__ == '__main__':
    raise SystemExit(main())
