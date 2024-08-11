
import { encodeAsync } from "cbor-web"

const keyLength = {
  '35': 16, // ...AES128GCM
} as Record<number | string, number>;

type PartyInfo = [Buffer | null, Buffer | number | null, Buffer | null]

const compute_PartyInfo = (identity: Buffer | null, nonce: Buffer | number | null, other: Buffer | null) => {
  return [
    identity || null, // identity
    nonce || null, // nonce
    other || null // other
  ] as PartyInfo
}

// https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.2
const compute_COSE_KDF_Context = (
  AlgorithmID: number,
  PartyUInfo: PartyInfo,
  PartyVInfo: PartyInfo,
  Protected: Buffer,
  SuppPrivInfo?: Buffer
) => {
  const info = [
    AlgorithmID, // AlgorithmID
    PartyUInfo,
    PartyVInfo,
    [ // SuppPubInfo
      keyLength[`${AlgorithmID}`] * 8, // keyDataLength
      Protected
    ]
  ]
  if (SuppPrivInfo) {
    (info as any).push(SuppPrivInfo)
  }
  return encodeAsync(info);
}


export const computeInfo = async (protectedHeader: Map<any, any>) => {
  let info = undefined;
  const algorithmId = protectedHeader.get(1)
  const partyUIdentity = protectedHeader.get(-21) || null
  const partyUNonce = protectedHeader.get(-22) || null
  const partyUOther = protectedHeader.get(-23) || null
  const partyVIdentity = protectedHeader.get(-24) || null
  const partyVNonce = protectedHeader.get(-25) || null
  const partyVOther = protectedHeader.get(-26) || null
  if (partyUNonce || partyVNonce) {
    info = await compute_COSE_KDF_Context(
      algorithmId,
      compute_PartyInfo(partyUIdentity, partyUNonce, partyUOther),
      compute_PartyInfo(partyVIdentity, partyVNonce, partyVOther),
      await encodeAsync(protectedHeader),
    )
  }
  return info
}
