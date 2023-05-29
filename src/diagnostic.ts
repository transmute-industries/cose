import * as cbor from 'cbor-web'

// const COSE_Sign1_TAG = 18
function toHexString(byteArray: Uint8Array) {
  return Array.prototype.map
    .call(byteArray, function (byte) {
      return ('0' + (byte & 0xff).toString(16)).slice(-2)
    })
    .join('')
}

const prettyHeaderKey = (k: string) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return ({
    [`1`]: 'alg',
    [`3`]: 'ctyp',
    [`4`]: 'kid',
    // new
    [`100`]: 'inclusion-proof',
    [`200`]: 'consistency-proof',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any)[`${k}`]
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const prettyHeaderValue = (v: any) => {
  const value = ({
    [`-7`]: '"ES256"',
    [`-35`]: '"ES384"',
    [`-36`]: '"ES512"',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any)[`${v}`]
  return value ? value : `h'${toHexString(new TextEncoder().encode(v))}'`
}

const diagnosticProtectedHeader = (data: Uint8Array) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const decoded = cbor.decode(data, { dictionary: 'map' } as any)
  const lines = []
  for (const [k, v] of decoded.entries()) {
    lines.push(`  #   "${prettyHeaderKey(k)}" : ${prettyHeaderValue(v)}`)
    lines.push(`  #   ${k} : ${v}`)
  }
  return `  # Protected Header
  h'${toHexString(data)}', 
  # {
${lines.join(',\n')}
  # }
`
}

const diagnosticData = (data: Uint8Array) => {
  return `h'${toHexString(data)}'`
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const diagnosticUnprotectedHeader = (decoded: any) => {
  if (!decoded.entries) {
    return '  # Unprotected Header\n  {},\n'
  }
  const lines = []
  for (const [k, v] of decoded.entries()) {
    lines.push(
      `    # "${prettyHeaderKey(k)}" : "${prettyHeaderValue(v)}"    
      ${k} : ${prettyHeaderValue(v)} `,
    )
  }
  return `  # Unprotected Header
  {
  ${lines.join(',\n')}
  },
`
}

const default_options = {
  decode_payload: true,
  detached_payload: false,
}
const alternateDiagnostic = async (
  data: Uint8Array,
  options = default_options,
) => {
  let diagnostic = ''
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { tag, value } = cbor.decode(data, { dictionary: 'map' } as any)
  const unprotectedHeader = diagnosticUnprotectedHeader(value[1])
  diagnostic += `# COSE_Sign1\n${tag}([\n\n`
  diagnostic += diagnosticProtectedHeader(value[0])
  diagnostic += '\n'
  diagnostic += unprotectedHeader
  diagnostic += '\n'
  if (options.detached_payload) {
    diagnostic += '  ' + '# Detached Payload\n'
  } else {
    diagnostic += '  ' + '# Protected Payload\n'
    diagnostic += '  ' + diagnosticData(value[2]) + ',\n'
    if (options.decode_payload) {
      diagnostic += '  ' + '# ' + new TextDecoder().decode(value[2]) + '\n'
    }
  }

  diagnostic += '\n'
  diagnostic += '  ' + '# Signature\n'
  diagnostic += '  ' + diagnosticData(value[3]) + '\n'
  diagnostic += `])`
  return diagnostic
}

export default alternateDiagnostic
