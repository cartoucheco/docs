# Cartouche API specification v2
## Endpoints

Requests are sent over HTTPS to https://api.cartouche.co/. A test environment will be available at https://api-test.cartouche.co/; submissions to this API will result in operations on the Ropsten test network instead of the Ethereum main network.

## Authentication

No direct authentication is required to access the API. Calls to endpoints such as /v2/associate require a cryptographic signature.

Message signing utilises the following procedure:
 - Arguments are represented as 256 bit values and concatenated. Numbers are big-endian. This is equivalent to using Ethereum ABI encoding.
 - The encoded data is hashed using keccak256.
 - A recoverable signature is generated using ECDSA-secp256k1, producing 256 bit r and s values, and a 1 bit v value. A 65-byte signature string is produced by representing r and s as 256 bit big-endian integers and concatenating them, followed by a single byte for v. In Ethereum signatures, 27 is added to the value of v before encoding - this is done for you by Ethereum-specific signature libraries.

## Generating a keypair
A script to generate a valid Ethereum keypair is available [here](tools/generate_key.py). The generated key file should be stored privately, and the output address provided to Cartouche for provisioning. The key generation script requires Python 3 and the ‘eth-account’ library, which can be installed with ‘pip3 install eth-account’.

## Signing messages
### Python

A sample script is available [here](tools/associate.py). This requires Python 3 and the ‘ens’, ‘web3’, ‘eth-abi’, ‘eth-account’ and ‘eth-utils’ libraries, which can be installed with pip3.

Generating a signature:
```
import json
from eth_abi import encode_abi
from eth_account import Account
from eth_utils import keccak

data = json.load(open('key.json'))
acct = Account.privateKeyToAccount(data['key'])

def signAssociateRequest(subnode, owner, nonce):
    encoded = encode_abi(
['bytes32', 'address', 'uint'],
[subnode, owner, nonce])
    hash = keccak(encoded)
    sig = acct.signHash(hash)
    return sig.signature.hex()
```
Example usage:
```
sig = signAssociateRequest(
    subnode,
    "0x314159265dd8dbb310642f98f50c066173c1259b",
    0)
```

subnode is generated using the namehash function. You can do this by calling the /v2/namehash endpoint, or by using functionality available in your language; for instance, in Python 3 with the web3.py NPM package installed:

```
from ens.utils import name_to_hash
subnode = name_to_hash(‘nic.luxe’)
```

### Java

An end to end Java sample is available [here](tools/java/src/main/java/co/cartouche/associate/Associate.java).

## Example Key
An example secp256k1 private key, encoded in hexadecimal, is as follows:

```
{"key": "0x6d8244cfdbe74e0979ea913f3250f515abc72de147935ddc554df9712aba85de", "address": "0x33637E446cbF4Ff540803dE3A314F57b0feebdaF"}
```

This key will be used throughout the examples below. Since message signing is deterministic, you can use these examples as test vectors for your own implementation.

## Request Format

Requests to all endpoints are sent as JSON-encoded messages. All requests are sent using the HTTP POST method, and must specify a `Content-Type` of `application/json`.

### Example request
A request to a hypothetical ‘echo’ endpoint might have the following body:

```
{"message": "Hello, world!"}
```

## Response Format

Responses are JSON objects, returned with `Content-Type: application/json`. All responses contain the following keys:
 - `error`: If an error occurred, this key is present, and is an object with the following keys:
 - `code`: An error code, as specified by the endpoint.
 - `message`: A human-readable error message.
 - `result`: If an error did not occur, this key is present and contains the result data (if any) specified by the endpoint.

### Example Responses

A successful call to the ‘echo’ endpoint might return a response like the following:
```
{"result": "Hello, world!"}
```
An unsuccessful call might return a response like the following:
```
{"error": {"code": 1, "message": "No message provided"}}
```

## Endpoints
### /v2/namehash
The namehash endpoint is provided for convenience, and produces the output of the ENS namehash function for a provided fully qualified domain name.

#### Request Format
Requests contain the following element:
 - `name` - The fully qualified name to hash.

#### Response Format
The namehash of the provided name is returned in the result field.

#### Example Request
```
$ curl -X POST -H "Content-Type: application/json" --data '{"name": "nic.luxe"}' http://api-test.cartouche.co/v2/namehash
```

An example response is as follows:
```
{"result": "0x8cf6312bc272d2fac9375e40cdd240b42b457bc7ba481725793e6b517f75772c"}
```

### /v2/nonce
The nonce endpoint retrieves the nonce value for a given domain. Nonces are used in order to prevent replay attacks on signed message; for an update to be accepted, it must have the expected nonce value, which starts at 0 and increases by 1 for each update message.

#### Request Format

Requests contain the following element:
 - `name` - The fully qualified name a nonce is being requested for.

#### Response Format

The current nonce for the domain is returned in the result field.

#### Example Request
```
$ curl -X POST -H "Content-Type: application/json" --data '{"name": "nic.luxe"}' http://api-test.cartouche.co/v2/nonce
```

An example response is as follows:

```
{"result": 0}
```

### /v2/associate
The associate endpoint establishes, updates or removes an association between a domain and an Ethereum address. It conducts the following operations:
 - Sets the provided address as the `owner` of the corresponding domain in ENS
 - Configures a default resolver for the domain.
 - Sets the provided address as the address to which the corresponding domain resolves.

To disassociate a name on ENS, send an associate request with an address consisting of all zeroes (0x0000000000000000000000000000000000000000).

#### Request format
Requests contain the following elements:
 - `domain` - The fully qualified name for which the associate request is being made (eg, ‘nic.luxe’).
 - `owner` - the Ethereum address with which the domain should be associated. This should be in the form ‘0x’ followed by 40 hexadecimal characters.
 - `nonce` - the nonce for this domain, retrieved with a call to /nonce
 - `signature` - A valid signature, as described below.

The signature field for this request comprises a cryptographic signature as described in the ‘Authentication’ section. The data to sign takes the following format:

| Bytes 0-31 | Bytes 32-43 | Bytes 44-63 | Bytes 64-95 |
| --- | --- | --- | --- |
| namehash(name) | Padding (0) | address | nonce |

Computation of namehash is described in EIP 137, and is implemented by libraries in a number of languages. For convenience, the /v2/namehash API is offered, which computes the same function.

The keccak256 hash of the above data is then signed using secp256k1, with the resulting signature packed as a 65 byte string:

| Bytes 0-31 | Bytes 32-63 | Byte 64 |
| --- | --- | --- |
| r | s | v + 27 |

All numerical values are big-endian.

#### Response Format
If the request succeeded, the string ‘ok’ is returned in the result field.

The following error codes are defined for failure conditions:
 - 429 - Too many requests. Updates to domain associations are ratelimited; try again later.
 - 400 - Bad request. A required parameter was not provided, or was in an invalid format or had an invalid value.

#### Example Request
We wish to make a request with the following parameters:

 - name: nic.luxe
 - address: 0x314159265dd8dbb310642f98f50c066173c1259b

First, a call is made to `/v2/nonce` (see the section on that RPC call for details), obtaining the current nonce for this domain. This is the first time we’ve updated the domain, so here it will be 0.

Next, we generate a signature. First, we obtain the namehash of ‘nic.luxe’, either by calling the `/v2/namehash` endpoint, or by using a library; for example:

```
from ens.utils import name_to_hash
node = name_to_hash(‘nic.luxe’)
```

Now, we encode the data to be signed - the name hash, address, and nonce. Each is represented as a 256 bit value, with integers in big-endian notation:

| node | address | nonce |
| --- | --- | --- |
| 8cf6312bc272d2fac9375e40cdd240b42b457bc7ba481725793e6b517f75772c | 000000000000000000000000314159265dd8dbb310642f98f50c066173c1259b |  0000000000000000000000000000000000000000000000000000000000000000 |

These values are concatenated, and hashed using keccak256:

```
hash = ‘0x803eaf9e7188e21c74192812ff217a6c5d4cf3778acda8460a04a1e29b1c8bd9’
```

A secp256k1 recoverable signature is generated from the hash, using our private key:

```
acct = Account.privateKeyToAccount(‘0x6d8244cfdbe74e0979ea913f3250f515abc72de147935ddc554df9712aba85de’)
sig = acct.signHash(hash)
```

The signature is encoded as a 65 byte string as described above in ‘authentication’. The Python library used in these examples does this automatically, providing it as `sig.signature`:

```
0x5fc7b774d1455a8a04c8d46f23ed7fe1de0b7e3bc9a1e02fa1058006829573d920f78d236b4793f2d184e7b6fe9efa19253731b645ca9f597d74d07944bb6ae71b
```

Finally, the name, address, nonce and signature are encoded in a JSON request and sent to the API server:

```
curl -X POST -H "Content-Type: application/json" --data '
{"name": "nic.luxe", "address": "0x314159265dd8dbb310642f98f50c066173c1259b", "nonce": 0, "signature": "0x5fc7b774d1455a8a04c8d46f23ed7fe1de0b7e3bc9a1e02fa1058006829573d920f78d236b4793f2d184e7b6fe9efa19253731b645ca9f597d74d07944bb6ae71b"}' http://api-test.cartouche.co/v2/associate
```

Assuming the authorisation check passes - eg, the message is signed with the public key associated with example.com - a success result is returned:

```
{"result": "ok"}
```

If the authorisation check fails, an error message like the following is returned:

```
{"error": {"code": 403, "message": "Could not verify message signature using the key provided for example.com"}}
```

### /v2/query
The query endpoint returns information on the current status of an ENS address.

#### Request Format
Requests contain the following element:
 - `name`: The name to query.

#### Response Format
If the request succeeded, a JSON object with the following entries is returned:
 - `owner` - The Ethereum address that owns the name in ENS.
 - `resolver` - The Ethereum address of the resolver contract responsible for this name.
 - `addr` - The Ethereum address to which the name resolves

#### Example Request

```
$ curl -X POST -H "Content-Type: application/json" --data '{"name": "nic.luxe"}' http://api-test.cartouche.co/v2/query
```

An example response is as follows:

```
{"result": {"owner": "0x466f6DE234aeca0e1Ae952588a6f908Ea3866a65", "resolver": "0x9eb3012d24e1E63E65655196D95F1018360Cab95", "addr": "0x466f6DE234aeca0e1Ae952588a6f908Ea3866a65"}}
```

### /v2/transactions
The transactions endpoint returns a list of associate operations made against ENS.

#### Request Format
Unlike other endpoints, this endpoint is accessed using GET, with arguments provided as query string parameters. The following parameters are supported:
 - `tld` (required) - The TLD to query (eg, 'luxe').
 - `start` (optional) - The nonce after which to begin the query. For pagination, supply the nonce of the last returned entry for this field.
 - `limit` (optional) - The number of results to return. Defaults to 100, maximum 1000.

#### Response Format
If the request succeeded, a list of JSON objects is returned. Each object has the following elements:
 - `tld` - The TLD for which the transaction was sent.
 - `timestamp` - The timestamp at which the transaction was sent.
 - `mined_at` - If mined, the timestamp at which the transaction was mined.
 - `block_number` - If mined, the block number at which the transaction was mined.
 - `hash` - The transaction hash. May change before a transaction is mined due to gas price changes.
 - `entries` - A list of entry objects. Each entry object has the following elements:
   - `name` - The name (without TLD) the associate operation affected.
   - `registrarId` - The ICANN ID of the registrar for that name. 
   - `owner` - The Ethereum address of the new owner for the name.

#### Example Request

```
$ curl http://api-test.cartouche.co/v2/transactions?tld=luxe
```

An example response is as follows:

```
{"result": [{"tld": "luxe", "timestamp": "2018-09-03T00:00:00", "entries": [{"name": "nic", "registrarId": 9999, "owner": "0x466f6DE234aeca0e1Ae952588a6f908Ea3866a65"]}]}
```

### /v2/ping
When sent a GET requests, returns 200 OK.

#### Example Request

```
$ curl http://api-test.cartouche.co/v2/ping
```

An example response is as follows:

```
OK
```
