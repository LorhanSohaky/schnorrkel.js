import { describe, expect, it } from 'vitest'

import { UnsafeSchnorrkel } from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing verify', () => {
  it('should verify signatures with custom protocol', () => {
    const schnorrkelOne = new UnsafeSchnorrkel()
    const schnorrkelTwo = new UnsafeSchnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces(keyPairOne.privateKey)
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces(keyPairTwo.privateKey)

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const combinedPublicKey = UnsafeSchnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)

    const msg = 'test message'
    const signatureOne = schnorrkelOne.multiSigSignWithHash(keyPairOne.privateKey, msg, combinedPublicKey, publicNonces)
    const signatureTwo = schnorrkelTwo.multiSigSignWithHash(keyPairTwo.privateKey, msg, combinedPublicKey, publicNonces)

    const signatures = [signatureOne.signature, signatureTwo.signature]
    const signaturesSummed = UnsafeSchnorrkel.sumSigs(signatures)
    const result = UnsafeSchnorrkel.verify(signaturesSummed, msg, signatureTwo.finalPublicNonce, combinedPublicKey.combinedKey)

    expect(result).toEqual(true)
  })

  it('should fail to verify signatures with custom protocol', () => {
    const schnorrkelOne = new UnsafeSchnorrkel()
    const schnorrkelTwo = new UnsafeSchnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const keyPairThree = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces(keyPairOne.privateKey)
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces(keyPairTwo.privateKey)

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const combinedPublicKey = UnsafeSchnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)
    const combinedPublicKeyTwo = UnsafeSchnorrkel.generateCombinedPublicKeyWithSalt([keyPairOne.publicKey, keyPairThree.publicKey])

    const msg = 'test message'
    const signatureOne = schnorrkelOne.multiSigSignWithHash(keyPairOne.privateKey, msg, combinedPublicKey, publicNonces)
    const signatureTwo = schnorrkelTwo.multiSigSignWithHash(keyPairTwo.privateKey, msg, combinedPublicKey, publicNonces)

    const signatures = [signatureOne.signature, signatureTwo.signature]
    const signaturesSummed = UnsafeSchnorrkel.sumSigs(signatures)
    const result = UnsafeSchnorrkel.verify(signaturesSummed, msg, signatureTwo.finalPublicNonce, combinedPublicKeyTwo.combinedKey)

    expect(result).toEqual(false)
  })
})