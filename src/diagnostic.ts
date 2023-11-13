import * as cbor from 'cbor-web'

const alternateDiagnostic = async (
  data: any
) => {
  const decoded = await cbor.decode(data)
  if (decoded.tag === 18 && decoded.value[2] === null) {
    decoded.value[2] = 'nil'
    const data2 = await cbor.encode(decoded)
    let text = await cbor.diagnose(data2, {
      separator: '\n'
    })
    text = text.replace(/"nil"/gm, 'nil')

    text = text.replace(/\(/gm, '(\n')
    text = text.replace(/\)/gm, '\n)')

    text = text.replace(/\[/gm, '[\n')
    text = text.replace(/\]/gm, '\n]')

    text = text.replace(/, /gm, ',\n')

    return text
  }
  let text = await cbor.diagnose(data, {
    separator: '\n'
  })
  text = text.replace(/\[/gm, '[\n')
  text = text.replace(/, /gm, ',\n')
  text = text.replace(/\]/gm, '\n]')
  return text

}

export default alternateDiagnostic
