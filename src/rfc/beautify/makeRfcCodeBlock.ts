export const makeRfcCodeBlock = (diagnostic: string) => {
  return `
~~~~ cbor-diag
${diagnostic.trim()}
~~~~
  `.trim()
}
