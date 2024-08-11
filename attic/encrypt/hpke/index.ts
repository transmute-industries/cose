import { decryptWrap, encryptWrap } from "./wrap"
import { decryptDirect, encryptDirect } from "./direct"

export * from './suites'

export const decrypt = {
  wrap: decryptWrap,
  direct: decryptDirect
}

export const encrypt = {
  direct: encryptDirect,
  wrap: encryptWrap
}
