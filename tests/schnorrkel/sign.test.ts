import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { generateRandomKeys } from '../../src/core'

describe('testing sign', () => {
  it('should generate signature', () => {
    const keyPair = generateRandomKeys()

    const msg = 'test message'
    const signature = Schnorrkel.sign(keyPair.privateKey, msg)

    expect(signature).toBeDefined()
    expect(signature.finalPublicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })
})