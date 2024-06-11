#!/usr/bin/env python3

import os
import pathlib
import json

from jwcrypto import jwk, jwt

PROJECT_DIR = pathlib.Path(os.path.dirname(__file__)).resolve()
KEY_STORE_PATH = PROJECT_DIR / "test_data" / "mock_private_keys.json"


def load_private_keys():
    with KEY_STORE_PATH.open() as fd:
        data: dict[str, dict[str, str]] = json.load(fd)

    for key, value in data.items():
        yield key, jwk.JWK.from_json(json.dumps(value))


def sign_mock_jwt(key_id: str, key: jwk.JWK):
    token = jwt.JWT(
        {
            "alg": "RS256",
            "kid": key_id,
        },
        {
            "foo": "bar",
            "bin": "baz",
        },
    )

    token.make_signed_token(key)

    return token.serialize()


def main():
    print(f"Generating JWTs using keys discovered in {KEY_STORE_PATH}\n")

    for key_id, key in load_private_keys():
        token = sign_mock_jwt(key_id, key)
        print(f" - {key_id}: {token}")


if __name__ == "__main__":
    main()
