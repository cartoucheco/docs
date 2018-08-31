"""
Sends an associate request to the Cartouche v2 API

Example usage:

 $ python tests/associate.py --keyfile=key.json domain.luxe 0x1234...
"""

import argparse
import json
import logging
import requests
from ens.utils import name_to_hash
from eth_abi import encode_abi
from eth_account import Account
from eth_utils import keccak


parser = argparse.ArgumentParser(description="Sends an associate request")
parser.add_argument('--keyfile', metavar='FILE', default='key.json', type=argparse.FileType('r'), help="Path to a file containing the key to sign with")
parser.add_argument('--url', metavar="URL", default="https://api-test.cartouche.co/", type=str)
parser.add_argument('domain', type=str)
parser.add_argument('address', type=str)


def sign_associate_request(acct, subnode, owner, nonce):
    encoded = encode_abi(
        ['bytes32', 'address', 'uint'],
        [subnode, owner, nonce])
    hash = keccak(encoded)
    sig = acct.signHash(hash)
    return sig.signature.hex()


def get_nonce(url, domain):
    response = requests.post(
        url + "v2/nonce",
        headers={"Content-Type": "application/json"},
        data=json.dumps({'name': domain,}))
    response.raise_for_status()
    nonce = response.json()['result']
    logging.debug("Got nonce %s", nonce)
    return nonce


def main(args):
    keydata = json.loads(args.keyfile.read())
    acct = Account.privateKeyToAccount(keydata['key'])
    nonce = get_nonce(args.url, args.domain)
    sig = sign_associate_request(acct, name_to_hash(args.domain), args.address, nonce)
    response = requests.post(
        args.url + "v2/associate",
        headers={"Content-Type": "application/json"},
        data=json.dumps({
            'domain': args.domain,
            'owner': args.address,
            'nonce': nonce,
            'signature': sig,
        })
    )
    if response.status_code != 200:
        logging.error("Server returned %d: %s", response.status_code, response.json()['error']['message'])
        return
    print(response.json()['result'])


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main(parser.parse_args())
