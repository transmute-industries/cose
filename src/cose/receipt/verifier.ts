import { ProtectedHeaderMap, PublicKeyJwk, RequestCoseSign1DectachedVerify } from "../sign1"

import { decodeFirstSync } from '../../cbor'

import { detached } from "../.."
import { get } from "./get"

import * as inclusion from './inclusion'
import { leaf } from "./leaf"
import { remove } from "./remove"

export type RequestHeaderVerifier = {
  resolve: (signature: ArrayBuffer) => Promise<PublicKeyJwk>
}

const getVerifierForMessage = async (req: RequestCoseSign1DectachedVerify, resolver: RequestHeaderVerifier) => {
  const verifier = detached.verifier({ resolver })
  return verifier
}

const verifyWithResolve = async (req: RequestCoseSign1DectachedVerify, opt: RequestHeaderVerifier) => {
  const verifier = await getVerifierForMessage(req, opt)
  const verified = await verifier.verify(req)
  return verified
}

export const verifier = async (opt: RequestHeaderVerifier) => {
  return {
    verify: async (req: RequestCoseSign1DectachedVerify) => {
      const verifiedPayload = await verifyWithResolve(req, opt)
      const verification = {
        payload: verifiedPayload,
        receipts: [] as ArrayBuffer[]
      }
      const bytesOnLedger = await remove(req.coseSign1)
      const receipts = await get(req.coseSign1)
      if (receipts.length) {
        for (const receipt of receipts) {
          const verifier = await getVerifierForMessage({
            coseSign1: receipt,
            payload: bytesOnLedger
          }, opt)
          const verifiedLedgerHead = await inclusion.verify({
            entry: await leaf(new Uint8Array(bytesOnLedger)),
            receipt,
            verifier
          })
          verification.receipts.push(verifiedLedgerHead)
        }
      }
      return verification
    }
  }
}