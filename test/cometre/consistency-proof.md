~~~~ cbor-diag
18(                                 / COSE Single Signer Data Object        /
    [
      h'a2012604...6d706c65',       / Protected header                      /
      {                             / Unprotected header                    /
        200: [                      / Consistency proofs (1)                /
          h'83040682...2e73a8ab',   / Consistency proof 1                   /
        ]
      },
      h'430b6fd7...f74c7fc4',       / Payload                               /
      h'72d74673...96792437'        / Signature                             /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected header                      /
  1: -7,                            / Cryptographic algorithm to use        /
  4: h'68747470...6d706c65'         / Key identifier                        /
}
~~~~

~~~~ cbor-diag
[                                   / Consistency proof 1                   /
  4,                                / Tree size 1                           /
  6,                                / Tree size 2                           /
  [                                 / Consistency hashes (2)                /
     h'0bdaaed3...32568964'         / Intermediate hash 1                   /
     h'75f177fd...2e73a8ab'         / Intermediate hash 2                   /
  ]
]
~~~~