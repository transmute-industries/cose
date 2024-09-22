

import { ellideBytes } from "./ellideBytes"
export const prettyPayload = (payload: ArrayBuffer | null) => {
  if (payload === null) {
    return 'null,'
  }
  return `${ellideBytes(payload)},`
}