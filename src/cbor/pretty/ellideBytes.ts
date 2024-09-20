export const ellideBytes = (bytes: Buffer) => {
  const line = `h'${bytes.toString('hex').toLowerCase()}'`
  return line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`).trim()
}
