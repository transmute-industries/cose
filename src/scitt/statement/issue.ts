

import detachPayload from '../../detachPayload'
import { typedArrayToBuffer } from '../../utils'
import * as key from '../../key'
import { SecretCoseKeyMap } from '../../key/types'
import getSigner from "../../lib/signer"

export type RequestScittSignedStatement = {
  iss: string
  sub: string
  cty: string
  x5c?: ArrayBuffer[]
  payload: ArrayBuffer
  signer?: any,
  secretCoseKey?: SecretCoseKeyMap
}

export const issue = async ({ iss, sub, cty, x5c, payload, signer, secretCoseKey }: RequestScittSignedStatement): Promise<ArrayBuffer> => {
  let receiptSigner = signer
  const protectedHeaderMap = new Map()
  const unprotectedHeaderMap = new Map()
  const cwtClaimsMap = new Map()
  cwtClaimsMap.set(1, iss)
  cwtClaimsMap.set(2, sub)
  if (x5c) {
    protectedHeaderMap.set(33, x5c) // x5chain https://www.iana.org/assignments/cose/cose.xhtml
  }
  if (secretCoseKey) {
    const secretKeyJwk = await key.exportJWK(secretCoseKey as any)
    secretKeyJwk.alg = key.utils.algorithms.toJOSE.get(secretCoseKey.get(3) as number)
    protectedHeaderMap.set(1, secretCoseKey.get(3) as number) // set alg from the restricted key
    protectedHeaderMap.set(3, cty) // content type of the payload
    protectedHeaderMap.set(4, secretCoseKey.get(2) as number) // set kid from the restricted key
    protectedHeaderMap.set(13, cwtClaimsMap)
    receiptSigner = getSigner({
      secretKeyJwk: secretKeyJwk as any
    })
  }
  const signedStatement = await receiptSigner.sign({
    protectedHeader: protectedHeaderMap,
    unprotectedHeader: unprotectedHeaderMap,
    payload
  })
  const { signature } = await detachPayload(signedStatement)
  return typedArrayToBuffer(signature)

}