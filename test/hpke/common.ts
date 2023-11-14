
import { AeadId, KdfId, KemId, CipherSuite, } from 'hpke-js'
import * as jose from 'jose'

export type Suite0 = `HPKE-Base-P256-SHA256-AES128GCM`
export const Suite0 = 'HPKE-Base-P256-SHA256-AES128GCM' as Suite0 // aka APPLE-HPKE-v1

export type PublicCoseKeyMap = Map<string | number, string | number | Buffer | ArrayBuffer>
export type SecretCoseKeyMap = Map<string | number, string | number | Buffer | ArrayBuffer>

export const encapsulated_key_header_label = -22222;
export const example_suite_label = -55555;


export const COSE_EncryptTag = 96

const suite0 = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
})

export const coseSuites = {
  [example_suite_label]: suite0,
} as Record<number, CipherSuite>

export const joseSuites = {
  [Suite0]: suite0,
} as Record<string, CipherSuite>


export type Suite0CurveName = `P-256`

export type SuiteNames = Suite0
export type CurveNames = Suite0CurveName


export const algToCrv = {
  [Suite0]: 'P-256',
} as Record<SuiteNames, CurveNames>


// https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1
// In both modes, the sender MUST specify the 'alg' parameter in the protected header to indicate the use of HPKE.

export const craftProtectedHeader = ({ alg, enc, kid }: { alg?: string, enc?: string, kid?: string }) => {
  return jose.base64url.encode(JSON.stringify({
    alg, enc, kid
  }))
}
