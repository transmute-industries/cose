
import { truncateBstr } from './truncateBstr'

export const beautifyInclusionProof = async (value: Buffer) => {
  const decoded = await truncateBstr(value)
  return `  100: ${decoded.trim()}`
}

/*

currently:

{
  100: [4, 2, [64(h'a39655d4...1f487bb1')]]
},

needs to be:

{
  100: [                       / inclusion proofs /
    4,                         / tree size /
    2,                         / leaf index /
    [
      h'a39655d4...1f487bb1'   / audit path hash /
    ]
  ]
},

*/