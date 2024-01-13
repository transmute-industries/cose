# COSE HPKE Wrap / 2 Layer

## Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74657374...792d3432',        / Identifier                    /
  3: 35,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'11198ff1...e6e82d47',       / x public key component        /
  -3: h'8779a21b...a2b5c32d',       / y public key component        /
  -4: h'35ca7789...a098af05',       / d private key component       /
}
~~~~

## Envelope

~~~~ cbor-diag
96([
  h'a10101',
  {
    5: h'1055c405225922b9be457289' / iv /
  },
  h'8cc01dfc141d2e79d7c77f47e344a8d14db3b93857e96952b4a1e8', / ciphertext /
  [
    [
      h'a10139d902',
      {
        4: "test-key-42",
        -4: h'0465031...c93fa9f' / encapsulated key /
      },
      h'9a78b4020d7320d7ffc9aff1f440acc7557a431497ff158dcc04b6644a20cda5' / encrypted key /
    ]
  ]
])
~~~~