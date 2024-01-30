import { DetachedSignature } from "./DetachedSignature"

export type CoseDetachedVerifier = {
  verify: ({ payload, signature }: DetachedSignature) => Promise<boolean>
}
