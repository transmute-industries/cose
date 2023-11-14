~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a3012604...65386e01',       / Protected                     /
      {                             / Unprotected                   /
        -222: {                     / Proofs                        /
          -2: [                     / Consistency proofs (1)        /
            h'83040682...2e73a8ab', / Consistency proof 1           /
          ]
        },
      },
      h'430b6fd7...f74c7fc4',       / Payload                       /
      h'7f66e095...3dd81b43'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: h'68747470...6d706c65',        / Key identifier                /
  -111: 1,                          / Verifiable Data Structure     /
}
~~~~

~~~~ cbor-diag
[                                   / Consistency proof 1           /
  4,                                / Tree size 1                   /
  6,                                / Tree size 2                   /
  [                                 / Consistency hashes (2)        /
     h'0bdaaed3...32568964'         / Intermediate hash 1           /
     h'75f177fd...2e73a8ab'         / Intermediate hash 2           /
  ]
]
~~~~