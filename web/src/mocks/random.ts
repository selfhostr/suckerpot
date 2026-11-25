/** Uniform number in [0, 1) from the Web Crypto API, for mock data (same contract as Math.random). */
export function mockRandom(): number {
  const buf = new Uint32Array(1)
  crypto.getRandomValues(buf)
  return (buf[0] ?? 0) / 2 ** 32
}
