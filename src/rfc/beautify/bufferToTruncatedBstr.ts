

export const bufferToTruncatedBstr = (thing: ArrayBuffer | Buffer | any) => {
  const buf = Buffer.from(thing)
  const line = `h'${buf.toString('hex').toLowerCase()}'`
  return line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`).trim()
}

