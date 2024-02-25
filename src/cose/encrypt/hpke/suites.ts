
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

export const primaryAlgorithm = {
  'label': `HPKE-Base-P256-SHA256-AES128GCM`,
  'value': 35
}

export const secondaryAlgorithm = {
  'label': `HPKE-Base-P384-SHA384-AES256GCM`,
  'value': 37
}

export const suites = {
  ['HPKE-Base-P256-SHA256-AES128GCM']: new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  }),
  ['HPKE-Base-P384-SHA256-AES128GCM']: new CipherSuite({
    kem: KemId.DhkemP384HkdfSha384,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })
}