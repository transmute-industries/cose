
import * as cbor from 'cbor-web'

import { ellideBytes } from './ellideBytes'

import { ec2_key, cose_key, cose_key_type, ec2, any_cose_key } from '../../iana/assignments/cose'

export const prettyCoseKey = (data: ArrayBuffer) => {
    const decoded = cbor.decode(data) as any_cose_key
    const kty = decoded.get(cose_key.kty as any) as any
    if (kty === cose_key_type.ec2) {
        const k = decoded as ec2_key
        let diag = `/ cose key / {\n`
        const kid = k.get(cose_key.kid)
        if (kid !== undefined) {
            diag += ` / kid /  ${cose_key.kid} : ${ellideBytes(kid)},\n`
        }
        const kty = k.get(ec2.kty)
        if (kty !== undefined) {
            diag += ` / kty /  ${cose_key.kty} : ${kty},\n`
        }
        const alg = k.get(cose_key.alg)
        if (kty !== undefined) {
            diag += ` / alg /  ${cose_key.alg} : ${alg},\n`
        }
        const crv = k.get(ec2.crv)
        if (crv !== undefined) {
            diag += ` / crv / ${ec2.crv} : ${crv},\n`
        }
        const x = k.get(ec2.x)
        if (x !== undefined) {
            diag += ` / x   / ${ec2.x} : ${ellideBytes(x as any)},\n`
        }
        const y = k.get(ec2.y)
        if (y && (typeof y !== "boolean")) {
            diag += ` / y   / ${ec2.y} : ${ellideBytes(y as any)},\n`
        }
        const d = k.get(ec2.d)
        if (d !== undefined) {
            diag += ` / d   / ${ec2.d} : ${ellideBytes(d as any)},\n`
        }
        diag += `}`
        return diag.trim()
    }
    return cbor.diagnose(data)
}

