import { ProtectedHeaderMap, PublicKeyJwk, RequestCoseSign1DectachedVerify } from "../sign1"

import { decodeFirstSync } from '../../cbor'

import { detached } from "../.."

export type RequestHeaderVerifier = {
  resolve: (protectedHeaderMap: ProtectedHeaderMap) => Promise<PublicKeyJwk>
}

export const verifier = async ({ resolve }: RequestHeaderVerifier) => {
  return {
    verify: async (req: RequestCoseSign1DectachedVerify) => {
      const { tag, value } = decodeFirstSync(req.coseSign1)
      if (tag !== 18) {
        throw new Error('Only tagged cose sign 1 are supported')
      }
      const [protectedHeaderBytes] = value;
      const protectedHeaderMap = decodeFirstSync(protectedHeaderBytes)
      const publicKeyJwk = await resolve(protectedHeaderMap);
      const verifier = detached.verifier({ publicKeyJwk })
      return verifier.verify(req)
    }
  }
}