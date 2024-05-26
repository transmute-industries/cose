Experimental implementation of JOSE / COSE HPKE for ML-KEM-68 ... filled with bugs, not a real implementation.

```cbor-diag
16([
  / protected / <<
    / algorithm / 1 : -777777 / HPKE-Base-ML-KEM-768-SHA256-AES128GCM /
  >>,
  / unprotected / {
    / key identifier /    4: "urn:ietf:params:oauth:ckt:sha-256:QcJhXe4j82YETvLzXQ5pXDtin541byZup5l0WuSC820",
    / encapsulated key / -4: h'f161ea5a094a55b21...6ae13e7e43613f'
  },
  / ciphertext / h'f224bd528704969d0ad5...6d0d27121a67e808c'
])
```
