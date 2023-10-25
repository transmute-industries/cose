
import cose from '../../src'

it('can generate cose keys', async () => {
  const jwkWithX509 = {
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:rPIgyCDF3oYrUNAUdpnMyowB95wbTmZ87j2Hvl4Ki6U",
    "kty": "EC",
    "crv": "P-384",
    "alg": "ES384",
    "x": "RFjeobDwgRClhn7skKDo7onzubCk5651i0NeYztnkZkXemHIA8FWIRyuRx5bymKJ",
    "y": "36rkwVggZTfYH54cUA9lrZXzm8-nM4wVUQ1jNLUuE6QqpwDk06qrp4ECVSXnbqJL",
    "x5c": [
      "MIIBtDCCATmgAwIBAgIBATAKBggqhkjOPQQDAzASMRAwDgYDVQQDEwdUZXN0IENBMB4XDTIwMDEwMTA2MDAwMFoXDTIwMDEwMzA2MDAwMFowIDENMAsGA1UEAxMEVGVzdDEPMA0GA1UECgwG0JTQvtC8MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERFjeobDwgRClhn7skKDo7onzubCk5651i0NeYztnkZkXemHIA8FWIRyuRx5bymKJ36rkwVggZTfYH54cUA9lrZXzm8+nM4wVUQ1jNLUuE6QqpwDk06qrp4ECVSXnbqJLo1UwUzAyBgNVHREEKzAphidkaWQ6d2ViOmlzc3Vlci5rZXkudHJhbnNwYXJlbmN5LmV4YW1wbGUwHQYDVR0OBBYEFJxDzabuhOvEV0KCtgVscBH8rysVMAoGCCqGSM49BAMDA2kAMGYCMQCuRQHv34V4pJktGRGzlG+N/uDSmOKe2hK50FcQ4UJ0SFokBlF8AHEQJpZzkqsZVBYCMQC6l7AxAwnkjOZn9SlI8VUkd6DGk5NTIZECANUCuErbPSLPgY/5hQJ5FMOHFCVLV/Q=",
      "MIIBvzCCAUagAwIBAgIBATAKBggqhkjOPQQDAzASMRAwDgYDVQQDEwdUZXN0IENBMB4XDTIwMDEwMTA2MDAwMFoXDTIwMDEwMzA2MDAwMFowEjEQMA4GA1UEAxMHVGVzdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABOCr6pdBrPA4/HI+JdzShWgajuQrJh2as2XOjU4TEVrXOqvAPLAEmtGz0TXj+d2mWYdcJ0sBcrUBzU34XNSPqurr1zXEZGHt+njznvnjL2AMTH3VaFJCtetGr5Wo9PYY+6NwMG4wTQYDVR0RBEYwRKAfBgkrBgEEAYI3GQGgEgQQrk8d+Ox90BGnZQCgyR5r9oYhZGlkOndlYjpyb290LnRyYW5zcGFyZW5jeS5leGFtcGxlMB0GA1UdDgQWBBSL/1Ew6Qs6FPc7tJh+2C1Eiae/1TAKBggqhkjOPQQDAwNnADBkAjBegrVtWuT91sfnJSWW3CAHxYy/vFN6Job0bwY26OR2B4RKRspWwlHVF1F5IKeDlqMCMGcHBurvdMSMAABllqBSTqJwyjH7kTCMh7XJQX9wSy1q1qwLkF1wyBemwD6CcoY1wA=="
    ]
  }
  const k1 = await cose.key.importJWK(jwkWithX509)
  const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(k1)
  expect(cktUri).toBe('urn:ietf:params:oauth:ckt:sha-256:NI0nSI1LGcQ68TT1wnWTKudKxd8IwcD3sEXWNTfEIOk')

  const diag = await cose.key.edn(k1)
  expect(diag.includes('-66666')).toBe(true) // private label for x5c


})
