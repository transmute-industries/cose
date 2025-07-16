/**
 * SCRAPI Transparency Configuration and JWKS resolver
 * See: https://ietf-wg-scitt.github.io/draft-ietf-scitt-scrapi/draft-ietf-scitt-scrapi.html#name-transparency-configuration
 */

export interface TransparencyConfiguration {
    jwks_uri: string
    [key: string]: any
}

export async function fetchTransparencyConfiguration(issuer: string): Promise<TransparencyConfiguration> {
    // If issuer is not a URL, prepend https://
    let base = issuer
    if (!/^https?:\/\//i.test(base)) {
        base = 'https://' + base
    }
    const configUrl = new URL('/.well-known/scitt/transparency-configuration', base)
    console.log('[SCRAPI] Fetching transparency configuration:', configUrl.toString())
    const res = await fetch(configUrl.toString())
    if (!res.ok) {
        throw new Error(`Failed to fetch transparency configuration: ${res.status} ${res.statusText}`)
    }
    const config = await res.json()
    if (!config.jwks_uri) {
        throw new Error('Transparency configuration missing jwks_uri')
    }
    return config as TransparencyConfiguration
}

export async function fetchJwksFromTransparencyConfig(issuer: string): Promise<any> {
    const config = await fetchTransparencyConfiguration(issuer)
    console.log('[SCRAPI] Fetching JWKS from:', config.jwks_uri)
    const res = await fetch(config.jwks_uri)
    if (!res.ok) {
        throw new Error(`Failed to fetch JWKS: ${res.status} ${res.statusText}`)
    }
    return await res.json()
} 