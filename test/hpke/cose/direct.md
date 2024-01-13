# COSE HPKE Direct / 1 Layer

## Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74657374...792d3432',        / Identifier                    /
  3: 35,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'e1cbfcf7...f8542800',       / x public key component        /
  -3: h'2537ece3...1c28e6d5',       / y public key component        /
  -4: h'4e9cbf1b...69f3cc86',       / d private key component       /
}
~~~~

## Envelope

~~~~ cbor-diag
96([
  h'a10139d902',
  {
    4: "test-key-42",
    -4: h'042b5c4...ed24ca04' / encapsulated key /
  },
  h'a054152691ebb37a679699be32e88979454aa474f87f05c866ad84' / cipher text /
])
~~~~