/**
 * SCRAPI Transparency Configuration and JWKS resolver
 * See: https://ietf-wg-scitt.github.io/draft-ietf-scitt-scrapi/draft-ietf-scitt-scrapi.html#name-transparency-configuration
 */

import * as cbor from '../../cbor'

export interface TransparencyConfiguration {
    issuer?: string
    jwks_uri: string
    [key: string]: any
}

// Fallback JWKS for known transparency services (fetched previously via curl)
const FALLBACK_JWKS: Record<string, any> = {
    'esrp-cts-cp.confidential-ledger.azure.com': {
        "keys": [
            {
                "crv": "P-384",
                "kid": "a7ad3b7729516ca443fa472a0f2faa4a984ee3da7eafd17f98dcffbac4a6a10f",
                "kty": "EC",
                "alg": "ES384",  // Add the algorithm for P-384 ECDSA
                "x": "m0kQ1A_uqHWuP9fdGSKatSq2brcAJ6-q3aZ5P35wjbgtNnlm2u-NLF1qM-yC4I2n",
                "y": "J9cJFrdWvUf6PCMkrWFTgB16uEq4mSMCI4NPVytnwYX6xNnuJ2GTrPtafKYg1VNi"
            }
        ]
    }
}

export async function fetchTransparencyConfiguration(issuer: string): Promise<TransparencyConfiguration> {
    // If issuer is not a URL, prepend https://
    let base = issuer
    if (!/^https?:\/\//i.test(base)) {
        base = 'https://' + base
    }
    const configUrl = new URL('/.well-known/scitt/transparency-configuration', base)
    // Fetch transparency configuration

    try {
        // Try with relaxed TLS settings for test environments
        const res = await fetch(configUrl.toString(), {
            // Add headers to handle different content types
            headers: {
                'Accept': 'application/cbor, application/json, */*'
            }
        })

        if (!res.ok) {
            throw new Error(`Failed to fetch transparency configuration: ${res.status} ${res.statusText}`)
        }

        // Check content type to determine parsing method
        const contentType = res.headers.get('content-type') || ''
        let config: TransparencyConfiguration

        if (contentType.includes('cbor') || contentType.includes('application/cbor')) {
            const buffer = await res.arrayBuffer()
            const decoded = cbor.decode(new Uint8Array(buffer))
            config = decoded as TransparencyConfiguration
        } else {
            // Try parsing as CBOR first (since CCF returns CBOR without proper content-type)
            const buffer = await res.arrayBuffer()
            try {
                const decoded = cbor.decode(new Uint8Array(buffer))
                config = decoded as TransparencyConfiguration
            } catch (cborError) {
                // Fallback to JSON if CBOR fails
                const text = new TextDecoder().decode(buffer)
                config = JSON.parse(text)
            }
        }

        if (!config.jwks_uri) {
            throw new Error('Transparency configuration missing jwks_uri')
        }

        console.log('[SCRAPI] Successfully parsed transparency configuration:', {
            issuer: config.issuer,
            jwks_uri: config.jwks_uri
        })

        return config

    } catch (error) {
        console.log(`[SCRAPI] Error fetching transparency configuration: ${error instanceof Error ? error.message : String(error)}`)
        throw error
    }
}

export async function fetchJwksFromTransparencyConfig(issuer: string): Promise<any> {
    // First, try the network approach
    try {
        const config = await fetchTransparencyConfiguration(issuer)
        console.log('[SCRAPI] Fetching JWKS from:', config.jwks_uri)

        const res = await fetch(config.jwks_uri, {
            headers: {
                'Accept': 'application/json, */*'
            }
        })

        if (!res.ok) {
            throw new Error(`Failed to fetch JWKS: ${res.status} ${res.statusText}`)
        }

        const jwks = await res.json()
        console.log(`[SCRAPI] Successfully fetched JWKS with ${jwks.keys?.length || 0} keys`)

        return jwks

    } catch (networkError) {
        console.log(`[SCRAPI] Network fetch failed: ${networkError instanceof Error ? networkError.message : String(networkError)}`)

        // Fallback to hardcoded JWKS for known services
        const normalizedIssuer = issuer.replace(/^https?:\/\//, '')
        const fallbackJwks = FALLBACK_JWKS[normalizedIssuer]

        if (fallbackJwks) {
            console.log(`[SCRAPI] Using fallback JWKS for ${normalizedIssuer} with ${fallbackJwks.keys?.length || 0} keys`)
            return fallbackJwks
        } else {
            console.log(`[SCRAPI] No fallback JWKS available for ${normalizedIssuer}`)
            throw new Error(`Failed to fetch JWKS for ${issuer}: ${networkError instanceof Error ? networkError.message : String(networkError)} (no fallback available)`)
        }
    }
} 