import * as cose from '../../index'
import * as cbor from '../../cbor'

/**
 * Interface for JWK (JSON Web Key)
 */
export interface JWK {
    kty: string
    kid: string
    use?: string
    key_ops?: string[]
    alg?: string
    x5u?: string
    x5c?: string[]
    x5t?: string
    'x5t#S256'?: string
    [key: string]: any
}

/**
 * Interface for JWKS (JSON Web Key Set)
 */
export interface JWKS {
    keys: JWK[]
}

/**
 * Interface for a trust store client that can fetch JWKS
 */
export interface TrustStoreClient {
    getJWKS(issuer: string): Promise<JWKS>
}

/**
 * Default implementation of TrustStoreClient using fetch
 */
export class DefaultTrustStoreClient implements TrustStoreClient {
    async getJWKS(issuer: string): Promise<JWKS> {
        try {
            // Patch: prepend https:// if issuer is just a hostname
            let base = issuer
            if (!/^https?:\/\//i.test(base)) {
                base = 'https://' + base
            }
            // Construct the JWKS URL from the issuer
            // For CCF services, the JWKS is typically available at /.well-known/jwks.json
            const jwksUrl = new URL('/.well-known/jwks.json', base)

            const response = await fetch(jwksUrl.toString())
            if (!response.ok) {
                throw new Error(`Failed to fetch JWKS from ${jwksUrl}: ${response.status} ${response.statusText}`)
            }

            const jwks = await response.json()
            return jwks as JWKS
        } catch (error) {
            throw new Error(`Failed to retrieve JWKS for issuer ${issuer}: ${error instanceof Error ? error.message : String(error)}`)
        }
    }
}

/**
 * Dynamic trust store that retrieves keys from service transparency configuration endpoints
 */
export class DynamicTrustStore {
    private client: TrustStoreClient
    private cache: Map<string, { jwks: JWKS, timestamp: number }> = new Map()
    private cacheTimeout: number = 5 * 60 * 1000 // 5 minutes

    constructor(client?: TrustStoreClient) {
        this.client = client || new DefaultTrustStoreClient()
    }

    /**
     * Get a public key from a receipt by looking up the service's JWKS
     */
    async getKey(receipt: Uint8Array): Promise<JWK> {
        // Parse the receipt to extract issuer and key ID
        const parsed = this.parseReceipt(receipt)
        const issuer = parsed.issuer
        const keyId = parsed.keyId

        // Get JWKS from cache or fetch from service
        const jwks = await this.getJWKS(issuer)

        // Find the key with matching kid
        const key = jwks.keys.find(k => k.kid === keyId)
        if (!key) {
            throw new Error(`Key ID ${keyId} not found in JWKS for issuer ${issuer}`)
        }

        return key
    }

    /**
     * Get JWKS for an issuer, using cache if available
     */
    private async getJWKS(issuer: string): Promise<JWKS> {
        const now = Date.now()
        const cached = this.cache.get(issuer)

        // Check if we have a valid cached entry
        if (cached && (now - cached.timestamp) < this.cacheTimeout) {
            return cached.jwks
        }

        // Fetch fresh JWKS
        const jwks = await this.client.getJWKS(issuer)

        // Cache the result
        this.cache.set(issuer, { jwks, timestamp: now })

        return jwks
    }

    /**
     * Parse a receipt to extract issuer and key ID
     */
    private parseReceipt(receipt: Uint8Array): { issuer: string, keyId: string } {
        try {
            const decoded = cbor.decode(receipt)
            if (decoded.tag !== 18) {
                throw new Error('Expected COSE Sign1 (tag 18)')
            }

            const protectedHeader = cbor.decode(decoded.value[0])
            const keyId = protectedHeader.get(cose.header.kid)
            const cwtClaims = protectedHeader.get(cose.header.cwt_claims)
            const issuer = cwtClaims.get(cose.cwt_claims.iss)

            if (!keyId || !issuer) {
                throw new Error('Missing key ID or issuer in receipt')
            }

            return { issuer, keyId }
        } catch (error) {
            throw new Error(`Failed to parse receipt: ${error instanceof Error ? error.message : String(error)}`)
        }
    }

    /**
     * Clear the cache
     */
    clearCache(): void {
        this.cache.clear()
    }

    /**
     * Set cache timeout in milliseconds
     */
    setCacheTimeout(timeout: number): void {
        this.cacheTimeout = timeout
    }
}

/**
 * Convert JWK to a format suitable for COSE verification
 */
export function jwkToCoseKey(jwk: JWK): any {
    // For now, return the JWK as-is since the COSE library should handle JWK format
    // In a more complete implementation, you might need to convert to a specific format
    return jwk
} 