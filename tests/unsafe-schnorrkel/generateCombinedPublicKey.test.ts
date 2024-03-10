import { describe, expect, it, expectTypeOf } from 'vitest'

import Schnorrkel, { Key } from '../../src/index'
import { _hashPrivateKey, generateRandomKeys, generateRandomSecret } from '../../src/core'

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

  it('should get same combined public key for same public keys wihtout secret', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const value1 = Schnorrkel.getCombinedPublicKey(publicKeys)
    const value2 = Schnorrkel.getCombinedPublicKey(publicKeys)

    expect(value1.combinedKey.toHex()).toEqual(value2.combinedKey.toHex())
    expect(value1.hashedKey).toEqual(value2.hashedKey)
  })

  it('should get same combined public key for same public keys with secret', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const hexSecret = '770198898C2E057E318AF0ECFCBB1404CB7DC844A4B6D357B94883759BCCD12C'

    const value1 = Schnorrkel.getCombinedPublicKey(publicKeys, hexSecret)
    const value2 = Schnorrkel.getCombinedPublicKey(publicKeys, hexSecret)

    expect(value1.combinedKey.toHex()).toEqual(value2.combinedKey.toHex())
    expect(value1.hashedKey).toEqual(value2.hashedKey)
  })

  it('should generate combined public key with secret', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    for (let i = 0; i < 1000; i++) {
      const secret = generateRandomSecret()
      expect(() => Schnorrkel.getCombinedPublicKey(publicKeys, secret)).not.toThrow()
    }
  })

  it('should throw error if secret is not a hex string', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const hexSecret = '#123'

    expect(() => Schnorrkel.getCombinedPublicKey(publicKeys, hexSecret)).toThrow('Secret should be a hex string')
  })
  it('should throw error if secret is empty', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const hexSecret = ''

    expect(() => Schnorrkel.getCombinedPublicKey(publicKeys, hexSecret)).toThrow('Secret cannot be empty')
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