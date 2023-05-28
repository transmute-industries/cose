import { PublicKeyJwk } from './PublicKeyJwk'
export type PrivateKeyJwk = PublicKeyJwk & {
  d: string
}
