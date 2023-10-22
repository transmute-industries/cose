## Dilithium COSE Sign 1

( this experimental )

### Public Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 7,                             / ✨ 7 is a new kty             /
  2: h'85eb5426...533214a2',        / Identifier                    /
  3: -55555,                        / Algorithm                     /
  -2: h'fbd0006c...f2f88c9c',       / ✨ need a new value for this  /
}
~~~~

### Protected Header

~~~~ cbor-diag
{                                   / Protected                     /
  1: -55555                         / ✨ -55555 is a new alg for    /
                                    / Dilithium 2                   /
}
~~~~

### Envelope

(no changes)

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a10139d902',                / Protected                     /
      {},                           / Unprotected                   /
      h'66616b65',                  / Payload                       /
      h'd471f7b9...1a27374c'        / Signature                     /
    ]
)
~~~~


