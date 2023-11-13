

export const bufferToTruncatedBstr = (thing: ArrayBuffer | Buffer | any) => {
  if (thing === null) {
    return 'nil'
  }
  const buf = Buffer.from(thing)
  const line = `h'${buf.toString('hex').toLowerCase()}'`
  return line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`).trim()
}

