import * as jose from 'jose'
import { CoseKeyMap } from './types';
import { importJWK } from './importJWK'
import keyUtils from './keyUtils'

export const generate = async (alg: number): Promise<CoseKeyMap> => {
  const joseAlg = keyUtils.algorithms.toJOSE.get(alg);
  if (!joseAlg) {
    throw new Error('Unsupported algorithm: ' + alg)
  }
  const cryptoKeyPair = await jose.generateKeyPair(joseAlg, { extractable: true });
  const secretKeyJwk = await jose.exportJWK(cryptoKeyPair.privateKey)
  const jwkThumbprint = await jose.calculateJwkThumbprint(secretKeyJwk)
  return importJWK({ ...secretKeyJwk, alg: joseAlg, kid: jwkThumbprint })
}