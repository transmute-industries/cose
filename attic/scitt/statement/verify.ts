

import { PublicCoseKeyMap } from '../../key/types'


import * as key from '../../key'
import getVerifier from "../../lib/verifier"
import attachPayload from '../../attachPayload'

export type RequestScittVerifySignedStatement = {

  statement: ArrayBuffer
  signedStatement: ArrayBuffer
  verifier?: any,
  publicCoseKey?: PublicCoseKeyMap
}

export const verify = async ({ statement, signedStatement, verifier, publicCoseKey }: RequestScittVerifySignedStatement): Promise<boolean> => {
  let statementVerifier = verifier
  if (publicCoseKey) {
    const publicKeyJwk = await key.exportJWK(publicCoseKey as any)
    publicKeyJwk.alg = key.utils.algorithms.toJOSE.get(publicCoseKey.get(3) as number)
    statementVerifier = getVerifier({
      publicKeyJwk: publicKeyJwk as any
    })
  }
  const attached = await attachPayload({
    signature: new Uint8Array(signedStatement),
    payload: new Uint8Array(statement)
  })
  try {
    const verifiedBytes = await statementVerifier.verify(attached)
    if (verifiedBytes) {
      return true
    } else {
      return false
    }
  } catch (e) {
    return false
  }
}