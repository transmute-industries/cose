~~~~ cbor-diag
18(                                 / COSE Single Signer Data Object        /
    [
      h'a3012604...392b6601',       / Protected header                      /
      {                             / Unprotected header                    /
        -22222: {                   / Proofs                                /
          1: [                      / Inclusion proofs (1)                  /
            h'83040282...1f487bb1', / Inclusion proof 1                     /
          ]
        },
      },
      h'',                          / Detached payload                      /
      h'b53e2c6a...cb3f43cb'        / Signature                             /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected header                      /
  1: -7,                            / Cryptographic algorithm to use        /
  4: h'68747470...6d706c65',        / Key identifier                        /
  -11111: 1                         / Verifiable data structure             /
}
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 1                     /
  4,                                / Tree size                             /
  2,                                / Leaf index                            /
  [                                 / Inclusion hashes (2)                  /
     h'a39655d4...d29a968a'         / Intermediate hash 1                   /
     h'57187dff...1f487bb1'         / Intermediate hash 2                   /
  ]
]
~~~~