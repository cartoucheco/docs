"""
Generates an Ethereum keypair

Example usage:

 $ python tests/generate_key.py outfile.json
"""

import argparse
import json
from eth_account import Account

parser = argparse.ArgumentParser(description="Generate an ECDSA keypair")
parser.add_argument('filename', type=str)


def main(args):
    acct = Account.create()
    f = open(args.filename, 'w')
    f.write(json.dumps({"key": acct.privateKey.hex(), "address": acct.address}))
    f.close()
    print("Wrote private key with address %s to %s" % (acct.address, args.filename))


if __name__ == '__main__':
    main(parser.parse_args())
