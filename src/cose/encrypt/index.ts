import * as direct from './direct'
import * as wrap from './wrap'

export const encrypt = {
  direct: direct.encrypt,
  wrap: wrap.encrypt
}

export const decrypt = {
  direct: direct.decrypt,
  wrap: wrap.decrypt
}