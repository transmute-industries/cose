export const bufferToTruncatedBstr = (buf: Buffer) => {
  const line = `h'${buf.toString('hex').toLowerCase()}'`
  return line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`).trim()
}

