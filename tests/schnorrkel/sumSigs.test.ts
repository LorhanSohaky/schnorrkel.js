import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing sumSigs', () => {
  it('should sum signatures', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces(keyPairOne.privateKey)
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces(keyPairTwo.privateKey)

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)

    const msg = 'test message'
    const signatureOne = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msg, combinedPublicKey, publicNonces)
    const signatureTwo = schnorrkelTwo.multiSigSign(keyPairTwo.privateKey, msg, combinedPublicKey, publicNonces)

    const signatures = [signatureOne.signature, signatureTwo.signature]
    const signature = Schnorrkel.sumSigs(signatures)

    expect(signature).toBeDefined()
    expect(signature.buffer).toHaveLength(32)
  })
})