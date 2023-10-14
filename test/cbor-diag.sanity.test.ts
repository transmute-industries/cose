
import transmute from '../src'

it("should tell you when you used Uint8Array wrong", async () => {
  const message = Buffer.from('deadbeef', 'hex')
  const encodedBuffer = transmute.cbor.web.encode(message)
  const encodedUint8Array = transmute.cbor.web.encode(new Uint8Array(message))
  const encodedBufferDiagnostic = await transmute.cbor.web.diagnose(encodedBuffer)
  expect(encodedBufferDiagnostic.trim()).toBe(`h'deadbeef'`) // expected
  const encodedUint8ArrayDiagnostic = await transmute.cbor.web.diagnose(encodedUint8Array)
  expect(encodedUint8ArrayDiagnostic.trim()).toBe(`64(h'deadbeef')`) // expected sometimes, but also wrong mostly
})