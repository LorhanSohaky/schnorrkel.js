import { describe, expect, it, expectTypeOf } from 'vitest'

import Schnorrkel, { Key } from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'

describe('testing getCombinedPublicKey', () => {
  it('should get combined public key', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const { combinedKey, hashedKey } = Schnorrkel.getCombinedPublicKey(publicKeys)

    expect(combinedKey).toBeDefined()
    expect(combinedKey).toBeInstanceOf(Key)
    expect(combinedKey.toHex()).toHaveLength(66)
    expect(hashedKey).toBeDefined()
    expectTypeOf(hashedKey).toBeString()
  })

  it('should get different combined public key for same public keys', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    type Output = ReturnType<typeof Schnorrkel.getCombinedPublicKey>
    const combinedKeys: Output['combinedKey'][] = []
    const hashedKeys: Output['hashedKey'][] = []

    for (let i = 0; i < 100; i++) {
      const value = Schnorrkel.getCombinedPublicKey(publicKeys)
      expect(combinedKeys).not.toContain(value.combinedKey)
      expect(hashedKeys).not.toContain(value.hashedKey)

      combinedKeys.push(value.combinedKey)
      hashedKeys.push(value.hashedKey)
    }
  })

  it('should get combined public key that is different from the original public keys', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey([keyPairOne.publicKey, keyPairTwo.publicKey])
    expect(combinedPublicKey.combinedKey.toHex()).not.toEqual(keyPairOne.publicKey.toHex())
    expect(combinedPublicKey.combinedKey.toHex()).not.toEqual(keyPairTwo.publicKey.toHex())
  })

  it('should throw error if less than 2 public keys are provided', () => {
    const keyPairOne = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey]

    expect(() => Schnorrkel.getCombinedPublicKey(publicKeys)).toThrow('At least 2 public keys should be provided')
  })
})