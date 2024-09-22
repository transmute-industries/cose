


function buf2hex(buffer: ArrayBuffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

export const ellideBytes = (bytes: ArrayBuffer) => {
  const line = `h'${buf2hex(bytes)}'`
  return line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`).trim()
}
