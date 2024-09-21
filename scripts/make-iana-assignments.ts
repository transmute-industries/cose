/* eslint-disable no-async-promise-executor */

import fs from 'fs';

import csv from 'csv-parser'

const cddlToType = (cddl: string) => {
  // invalid cddl in iana registry
  if (cddl.includes('array')) {
    return cddl
      .replace("array (of array of uint)", "Array<Array<number>>")
      .replace("array (of uint)", "Array<number>")
      .replace("array (of number)", "Array<number>")
      .replace("array", "Array<any>")
  }
  if (cddl.length) {
    return cddl
      .replace(/\//g, '|')
      .replace(/tstr/g, 'string')
      .replace(/bstr/g, 'Buffer')
      .replace(/uint/g, 'number')
      .replace(/int/g, 'number')
      .replace(/bool/g, 'boolean')
      .replace(/\+/g, '')
  }
  return 'string'
}

const curveLabels = [] as any
const commonKeyParamsMap = new Map()

const getCommonKeyParams = () => {
  return new Promise(async (resolve) => {
    // https://www.iana.org/assignments/cose/key-common-parameters.csv
    const stream = fs.createReadStream('./scripts/data/key-common-parameters.csv')
      .pipe(csv())
    const commonKeyParams = {} as any
    let commonKeyParamDefinitions = `\n`
    stream.on('data', (row: any) => {
      if (row.Label.includes('-')) {
        return
      }
      if (row.Reference.startsWith('[RFC')) {
        row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
      }
      const valueName = row.Name.replace(/ /g, '_').toLowerCase()
      const valueType = cddlToType(row['CBOR Type'])
      commonKeyParams[row['Label']] = [valueName, valueType]
      commonKeyParamDefinitions += `
export const ${valueName}_key_parameter = {
  'Name': '${row['Name']}',
  'Label': ${row['Label']},
  'CBOR Type': '${row['CBOR Type']}',
  'Value Registry': '${row['Value Registry']}',
  'Description': '${row['Description'].replace(/\\n/g, ' ')}',
  'Reference': '${row['Reference']}'
}
  `.trim() + '\n'
    });
    stream.on('end', () => {
      commonKeyParamDefinitions += `export enum cose_key {\n`
      for (const entry of Object.entries(commonKeyParams)) {
        const [label, [name, type]] = entry as any
        if (label <= 0) {
          continue
        }
        commonKeyParamDefinitions += `  ${name} = ${label},\n`
        commonKeyParamsMap.set(parseInt(label, 10), name)
      }
      commonKeyParamDefinitions += '}\n'
      commonKeyParamDefinitions = commonKeyParamDefinitions.trim()
      resolve({ commonKeyParams, commonKeyParamDefinitions })
    });
  })
}

const getKeyTypes = async () => {
  return new Promise(async (resolve) => {
    // https://www.iana.org/assignments/cose/key-type.csv
    const stream = fs.createReadStream('./scripts/data/key-type.csv')
      .pipe(csv())
    let keyTypeDefinitions = `\n`
    const keyTypes = new Map()
    stream.on('data', (row: any) => {
      if (row.Reference.startsWith('[RFC')) {
        const matches = row.Reference.match(/[(RFC\d+)]+/g)
        if (matches.length) {
          row.Reference = matches.map((rfc: any) => {
            return `https://datatracker.ietf.org/doc/${rfc.toLowerCase()}`
          }).join(' ')
        }
      }
      row['Value'] = parseInt(row['Value'], 10)
      const valueName = row['Name'].replace(/ /g, '_').replace(/-/g, '_').toLowerCase()
      keyTypeDefinitions += `
export const ${valueName}_key_type = {
  'Name': '${row['Name']}',
  'Value': ${row['Value']},
  'Description': '${row['Description'].replace(/\n /g, ' ')}',
  'Capabilities': '${row['Capabilities']}',
  'Reference': '${row['Reference']}'
}
  `.trim() + '\n'
      const k = new Map()
      k.set(1, ['kty', row['Value']])
      keyTypes.set(row['Value'], [valueName, k])
    });
    stream.on('end', () => {
      keyTypeDefinitions += `export enum cose_key_type {\n`
      for (const [label, [name, type]] of keyTypes.entries()) {
        if (label <= 0) {
          continue
        }
        keyTypeDefinitions += `  ${name} = ${label},\n`
      }
      keyTypeDefinitions += '}\n'
      return resolve({ keyTypes, keyTypeDefinitions })
    });
  })
}

const getCurves = async () => {
  return new Promise(async (resolve) => {
    // https://www.iana.org/assignments/cose/elliptic-curves.csv
    const stream = fs.createReadStream('./scripts/data/elliptic-curves.csv')
      .pipe(csv())
    let curveDefinitions = `\n`
    const curvesByKeyType = new Map()
    stream.on('data', (row: any) => {
      if (row.Value.includes('-')) {
        return
      }
      if (row.Reference.startsWith('[RFC')) {
        const matches = row.Reference.match(/[(RFC\d+)]+/g)
        if (matches.length) {
          row.Reference = matches.map((rfc: any) => {
            return `https://datatracker.ietf.org/doc/${rfc.toLowerCase()}`
          }).join(' ')
        }
      }
      row['Value'] = parseInt(row['Value'], 10)
      const valueName = row['Name'].replace(/ /g, '_').replace(/-/g, '_').toLowerCase()
      if (curvesByKeyType.get(row['Key Type']) === undefined) {
        curvesByKeyType.set(row['Key Type'], new Map())
      }
      const curvesForKeyType = curvesByKeyType.get(row['Key Type'])
      curvesForKeyType.set(valueName, row['Value'])
      curvesByKeyType.set(row['Key Type'], curvesForKeyType)
      curveDefinitions += `
export const ${valueName}_curve = {
  'Name': '${row['Name']}',
  'Value': ${row['Value']},
  'Key Type': '${row['Key Type']}',
  'Description': '${row['Description'].replace(/\n /g, ' ')}',
  'Change Controller': '${row['Change Controller']}',
  'Reference': '${row['Reference']}',
  'Recommended': '${row['Recommended']}'
}
        `.trim() + '\n'
    });
    stream.on('end', () => {
      // create enums for key types

      for (const [kty, curves] of curvesByKeyType.entries()) {
        if (kty === '') {
          continue
        }
        curveDefinitions += `export enum ${kty.toLowerCase()}_curves {\n`
        for (const [curveName, curveLabel] of curves.entries()) {
          curveDefinitions += `  ${curveName} = ${curveLabel},\n`
          let joseCurveName = curveName.replace('_', '-')
          if (joseCurveName.includes('-')) {
            joseCurveName = joseCurveName.toUpperCase()
          }
          if (joseCurveName.startsWith('x') || joseCurveName.startsWith('e')) {
            joseCurveName = joseCurveName.charAt(0).toUpperCase() + joseCurveName.slice(1);
          }
          curveLabels.push([curveLabel, joseCurveName])

        }
        curveDefinitions += '}\n'
      }
      return resolve({ curvesByKeyType, curveDefinitions })
    });
  })
}

const getKeyTypeParams = async ({ commonKeyParams, keyTypes, curvesByKeyType }: any) => {
  const paramsByKeyType = new Map()
  // https://www.iana.org/assignments/cose/key-type-parameters.csv
  return new Promise(async (resolve) => {
    const stream = fs.createReadStream('./scripts/data/key-type-parameters.csv')
      .pipe(csv())
    let keyParams = `\n`
    stream.on('data', row => {
      if (row.Reference.startsWith('[RFC')) {
        row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
      }
      row['Key Type'] = parseInt(row['Key Type'], 10)
      row['Label'] = parseInt(row['Label'], 10)
      // this is later used to produce fully specified key types
      const [ktyName, ktyParams] = keyTypes.get(row['Key Type'])
      const paramName = row['Name'].replace(/ /g, '_').replace(/-/g, '_').toLowerCase()
      const valueType = cddlToType(row['CBOR Type'])
      ktyParams.set(row['Label'], [paramName, valueType])
      keyParams += `
export const ${ktyName}_${paramName}_parameter = {
  'Key Type': ${row['Key Type']},
  'Label': ${row['Label']},
  'Name': '${row['Name']}',
  'CBOR Type': '${row['CBOR Type']}',
  'Description': '${row['Description'].replace(/\n /g, ' ')}',
  'Reference': '${row['Reference']}'
}
`.trim() + '\n'

    });
    stream.on('end', () => {



      // create enums for key types
      for (const [kty, [name, params]] of keyTypes.entries()) {
        // skip reserved
        if (kty === 0) {
          continue
        }
        const keyName = `${name}`
        keyParams += `export enum ${keyName} {\n`
        // merge enums here.
        for (const entry of Object.entries(commonKeyParams)) {
          const [label, [name, type]] = entry as any
          if (label === '0') {
            continue
          }
          keyParams += `  ${name} = ${label},\n`
        }
        for (const [paramLabel, [paramName]] of params.entries()) {
          if (paramName === 'kty') {
            continue
          }
          keyParams += `  ${paramName} = ${paramLabel},\n`
        }
        keyParams += '}\n\n'
      }

      keyParams += `\nexport type any_cose_key = Map<any, any> & {\n`
      for (const entry of Object.entries(commonKeyParams)) {
        const [label, [tag, type]] = entry as any
        if (label === '0') {
          continue
        }
        // skip kty
        if (label === '1') {
          continue
        }
        keyParams += `  get(k: cose_key.${tag}): ${type}\n`
      }
      keyParams += '}\n\n'
      for (const [kty, [name, params]] of keyTypes.entries()) {
        // skip reserved
        if (kty === 0) {
          continue
        }
        const keyName = `${name}_key`
        const keyTypeParams = new Map(commonKeyParamsMap.entries())


        keyParams += `export type ${keyName} = any_cose_key & {\n`
        for (const [paramLabel, [paramTag, paramValue]] of params.entries()) {
          if (paramLabel === 1) {
            const [keyType] = keyTypes.get(paramValue)
            keyParams += `  get(k: ${name}.${paramTag}): cose_key_type.${keyType}\n`
          } else {
            if (paramTag === 'crv') {
              keyParams += `  get(k: ${name}.${paramTag}): ${name}_curves\n`
            } else {
              keyParams += `  get(k: ${name}.${paramTag}): ${paramValue}\n`
            }
          }

          keyTypeParams.set(paramLabel, paramTag)
        }
        keyParams += '}\n\n'
        paramsByKeyType.set(kty, keyTypeParams)
      }
      keyParams = keyParams.trim()

      return resolve({ keyParams, paramsByKeyType })
    });
  })
}




const createAlgorithmDefinitions = () => {
  const labelToAlgorithm = new Map() as Map<number, string>
  return new Promise(async (resolve) => {
    const stream = fs.createReadStream('./scripts/data/algorithms.csv')
      .pipe(csv())
    let algorithmDefinitions = `\n`
    stream.on('data', (row: any) => {
      if (row.Name === 'Unassigned' || row.Name.includes('Reserved')) {
        return
      }
      const valueName = row.Name
        .replace(/ /g, '_')
        .replace(/-/g, '_')
        .replace(/\//g, '_')
        .replace(/\+/g, '_')
        .toLowerCase()
      if (row.Reference.startsWith('[RFC')) {
        row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
      }
      row['Value'] = parseInt(row['Value'], 10)
      algorithmDefinitions += `
export const ${valueName}_algorithm = {
  'Name': '${row['Name']}',
  'Value': ${row['Value']},
  'Description': '${row['Description'].replace(/\\n/g, ' ')}',
  'Capabilities': '${row['Capabilities']}',
  'Change Controller': '${row['Change Controller']}',
  'Reference': '${row['Reference']}',
  'Recommended': '${row['Recommended']}'
}
        `.trim() + '\n'
      labelToAlgorithm.set(row['Value'], row['Name'])
    });
    stream.on('end', () => {
      algorithmDefinitions += `export enum algorithm {\n`
      for (const [label, name] of labelToAlgorithm.entries()) {
        let betterName = name.split(' (')[0]
        betterName = betterName
          .replace(/ /g, '_')
          .replace(/-/g, '_')
          .replace(/\+/g, '_')
          .replace(/\//g, '_')
        betterName = betterName.toLowerCase()
        algorithmDefinitions += `  ${betterName} = ${label},\n`
      }
      algorithmDefinitions += `}\n`
      resolve({ labelToAlgorithm, algorithmDefinitions })
    });
  })
}


const createHeaderParamesters = () => {
  const labelToHeaderParam = new Map() as Map<number, string>
  return new Promise(async (resolve) => {
    const stream = fs.createReadStream('./scripts/data/header-parameters.csv')
      .pipe(csv())
    let headerParameterDefinitions = `\n`
    stream.on('data', (row: any) => {
      if (row.Name === 'Unassigned' || row.Name.includes('Reserved') || row.Name.includes('delegated')) {
        return
      }
      const valueName = row.Name
        .replace(/ /g, '_')
        .replace(/-/g, '_')
        .replace(/\//g, '_')
        .replace(/\(/g, '_')
        .replace(/\)/g, '_')
        .replace(/\+/g, '_')
        .toLowerCase()
      if (row.Reference.startsWith('[RFC')) {
        row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
      }
      row['Label'] = parseInt(row['Label'], 10)
      headerParameterDefinitions += `
export const ${valueName}_algorithm = {
  'Name': '${row['Name']}',
  'Label': ${row['Label']},
  'Value Type': '${row['Value Type'].replace(/\\n/g, ' ')}',
  'Value Registry': '${row['Value Registry']}',
  'Change Controller': '${row['Change Controller']}',
  'Description': "${row['Description']}",
  'Reference': '${row['Reference']}'
}
              `.trim() + '\n'
      labelToHeaderParam.set(row['Label'], row['Name'])
    });
    stream.on('end', () => {
      headerParameterDefinitions += `export enum header {\n`
      for (const [label, name] of labelToHeaderParam.entries()) {
        let betterName = name.split(' (')[0]
        betterName = betterName.replace(/ /g, '_')
        betterName = betterName.toLowerCase()
        headerParameterDefinitions += `  ${betterName} = ${label},\n`
      }
      headerParameterDefinitions += `}\n`
      resolve({ labelToHeaderParam, headerParameterDefinitions })
    });
  })
}

const createMappings = (
  curveLabels: [number, string][],
  paramsByKeyType: Map<any, any>,
  keyTypes: Map<any, any>,
  labelToAlgorithm: Map<number, string>,
  labelToHeaderParam: Map<number, string>
) => {

  const ktyMap = {
    'okp': 'OKP',
    'ec2': 'EC',
    'rsa': 'RSA',
    'symmetric': 'oct'
  } as Record<string, any>

  const ktyNames = Array.from(keyTypes.entries()).map(([label, [name]]) => {
    const betterName = ktyMap[name] ? ktyMap[name] : name
    return [label, betterName]
  })
  let mappings = `

// kty
export const label_to_key_type = new Map(${JSON.stringify(ktyNames)}) as Map<number,string>
export const key_type_to_label = new Map([...label_to_key_type.entries()].map((e: any) => e.reverse())) as Map<string, number>

// crv
export const label_to_curve = new Map(${JSON.stringify(curveLabels)}) as Map<number, string>
export const curve_to_label = new Map([...label_to_curve.entries()].map((e: any) => e.reverse())) as Map<string, number>

// alg
export const labels_to_algorithms = new Map(${JSON.stringify(Array.from(labelToAlgorithm.entries()))}) as Map<number, string>
export const algorithms_to_labels = new Map([...${`labels_to_algorithms`}.entries()].map((e: any) => e.reverse())) as Map<string, number>

// headers
export const labels_to_headers = new Map(${JSON.stringify(Array.from(labelToHeaderParam.entries()))}) as Map<number, string>
export const headers_to_labels = new Map([...${`labels_to_headers`}.entries()].map((e: any) => e.reverse())) as Map<string, number>
`

  for (const [kty, params] of paramsByKeyType.entries()) {
    const [ktyName] = keyTypes.get(kty)
    mappings += `
// ${ktyName}
export const labels_to_${ktyName}_params = new Map(${JSON.stringify(Array.from(params.entries()))}) as Map<number, string>
export const ${ktyName}_params_to_labels = new Map([...${`labels_to_${ktyName}_params`}.entries()].map((e: any) => e.reverse())) as Map<string, number>
`
  }
  return mappings
}



(async () => {
  const { commonKeyParams, commonKeyParamDefinitions } = await getCommonKeyParams() as any
  const { keyTypes, keyTypeDefinitions } = await getKeyTypes() as any
  const { curvesByKeyType, curveDefinitions } = await getCurves() as any
  const { keyParams, paramsByKeyType } = await getKeyTypeParams({ commonKeyParams, keyTypes, curvesByKeyType }) as any

  const { labelToAlgorithm, algorithmDefinitions } = await createAlgorithmDefinitions() as any
  const { labelToHeaderParam, headerParameterDefinitions } = await createHeaderParamesters() as any;
  const mappings = createMappings(curveLabels, paramsByKeyType, keyTypes, labelToAlgorithm, labelToHeaderParam)
  const final = `
// DO NOT edit this file, it is generated automatically
${commonKeyParamDefinitions}
${keyTypeDefinitions}
${curveDefinitions}
${algorithmDefinitions}
${headerParameterDefinitions}
${keyParams}
${mappings}

`.trim()
  fs.writeFileSync('./src/iana/assignments/cose.ts', final)
})()