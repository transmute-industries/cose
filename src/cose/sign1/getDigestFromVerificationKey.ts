
const joseToCose = new Map<string, string>()

// ECDSA algorithms
joseToCose.set('ES256', `SHA-256`)
joseToCose.set('ES384', `SHA-384`)
joseToCose.set('ES512', `SHA-512`)

// RSA-PSS algorithms (RFC 8230)
joseToCose.set('PS256', `SHA-256`)
joseToCose.set('PS384', `SHA-384`)
joseToCose.set('PS512', `SHA-512`)

// fully specified
joseToCose.set('ESP256', `SHA-256`)
joseToCose.set('ESP384', `SHA-384`)

const getDigestFromVerificationKey = (alg: string): string => {
    const digestAlg = joseToCose.get(alg)
    if (!digestAlg) {
        throw new Error('This library requires keys to contain fully specified algorithms')
    }
    return digestAlg
}

export default getDigestFromVerificationKey