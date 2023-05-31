import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing multiSigSign', () => {
  it('should generate multi signature', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces(keyPairOne.privateKey)
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces(keyPairTwo.privateKey)

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const combinedKey = Schnorrkel.getCombinedPublicKey(publicKeys)

    const msg = 'test message'
    const signature = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msg, combinedKey, publicNonces)

    expect(signature).toBeDefined()
    expect(signature.finalPublicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })

  it('should requires nonces', () => {
    const schnorrkel = new Schnorrkel()
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()

    const msg = 'test message'
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const combinedKey = Schnorrkel.getCombinedPublicKey(publicKeys)

    expect(() => schnorrkel.multiSigSign(keyPairOne.privateKey, msg, combinedKey, [])).toThrowError('Nonces should be exchanged before signing')
  })
})