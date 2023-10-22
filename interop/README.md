
# Proposal

[Read the draft](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 7,                             / ✨ 7 is MLWE                  /
  2: h'85eb5426...533214a2',        / Identifier                    /
  3: -55555,                        / ✨ -55555 is CRYDI2           /
  -13: h'fbd0006c...f2f88c9c',      / ✨ private key for 7          /
  -14: h'fbd0006c...f2f88c9c',      / ✨ public key for 7           /
}
~~~~

## Current

### Public Key
{                                   / COSE Key                      /
  1: 7,                             / Type                          /
  2: h'fac56e1c...ae984e0a',        / Identifier                    /
  3: -55555,                        / Algorithm                     /
  -14: h'7803c0f9...3bba7abd',      / Post quantum public key       /
}

### Secret Key
{                                   / COSE Key                      /
  1: 7,                             / Type                          /
  2: h'fac56e1c...ae984e0a',        / Identifier                    /
  3: -55555,                        / Algorithm                     /
  -13: h'7803c0f9...3f6e2c70',      / Post quantum private key      /
  -14: h'7803c0f9...3bba7abd',      / Post quantum public key       /
}

### Envelope

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a10139d902',                / Protected                     /
      {},                           / Unprotected                   /
      h'66616b65',                  / Payload                       /
      h'53e855e8...0f263549'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -55555                         / Algorithm                     /
}
~~~~

  