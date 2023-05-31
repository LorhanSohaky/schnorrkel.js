import { describe, expect, it, expectTypeOf } from 'vitest'

import { Key, UnsafeSchnorrkel } from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'

describe('testing generateCombinedPublicKeyWithSalt', () => {
  it('should generate combined public key', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const { combinedKey, hashedKey } = UnsafeSchnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)

    expect(combinedKey).toBeDefined()
    expect(combinedKey).toBeInstanceOf(Key)
    expect(combinedKey.toHex()).toHaveLength(66)
    expect(hashedKey).toBeDefined()
    expectTypeOf(hashedKey).toBeString()
  })

  it('should throw error if less than 2 public keys are provided', () => {
    const keyPairOne = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey]

    expect(() => UnsafeSchnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)).toThrow('At least 2 public keys should be provided')
  })

  it('should generate different combined public key for same public keys', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    type Output = ReturnType<typeof UnsafeSchnorrkel.generateCombinedPublicKeyWithSalt>
    const combinedKeys: Output['combinedKey'][] = []
    const hashedKeys: Output['hashedKey'][] = []

    for (let i = 0; i < 100; i++) {
      const value = UnsafeSchnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)
      expect(combinedKeys).not.toContain(value.combinedKey)
      expect(hashedKeys).not.toContain(value.hashedKey)

      combinedKeys.push(value.combinedKey)
      hashedKeys.push(value.hashedKey)
    }
  })
})