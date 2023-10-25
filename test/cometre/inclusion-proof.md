~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a3012604...65386e01',       / Protected                     /
      {                             / Unprotected                   /
        -222: {                     / Proofs                        /
          -1: [                     / Inclusion proofs (1)          /
            h'83040282...1f487bb1', / Inclusion proof 1             /
          ]
        },
      },
      h'',                          / Detached payload              /
      h'6596e238...082ab5e9'        / Signature                     /
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
[                                   / Inclusion proof 1             /
  4,                                / Tree size                     /
  2,                                / Leaf index                    /
  [                                 / Inclusion hashes (2)          /
     h'a39655d4...d29a968a'         / Intermediate hash 1           /
     h'57187dff...1f487bb1'         / Intermediate hash 2           /
  ]
]
~~~~