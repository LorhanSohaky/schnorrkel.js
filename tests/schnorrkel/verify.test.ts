import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing verify', () => {
  it('should verify signatures', () => {
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
    const signaturesSummed = Schnorrkel.sumSigs(signatures)
    const result = Schnorrkel.verify(signaturesSummed, msg, signatureTwo.finalPublicNonce, combinedPublicKey.combinedKey)

    expect(result).toEqual(true)
  })

  it('should fail to verify signatures', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const keyPairThree = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces(keyPairOne.privateKey)
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces(keyPairTwo.privateKey)

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const combinedPublicKeyTwo = Schnorrkel.getCombinedPublicKey([keyPairOne.publicKey, keyPairThree.publicKey])

    const msg = 'test message'
    const signatureOne = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msg, combinedPublicKey, publicNonces)
    const signatureTwo = schnorrkelTwo.multiSigSign(keyPairTwo.privateKey, msg, combinedPublicKey, publicNonces)

    const signatures = [signatureOne.signature, signatureTwo.signature]
    const signaturesSummed = Schnorrkel.sumSigs(signatures)
    const result = Schnorrkel.verify(signaturesSummed, msg, signatureTwo.finalPublicNonce, combinedPublicKeyTwo.combinedKey)

    expect(result).toEqual(false)
  })

  it('should fail to verify signatures with wrong key pair', () => {
    const schnorrkelClient = new Schnorrkel()
    const schnorrkelServer = new Schnorrkel()

    const keyPairServer = generateRandomKeys()

    const sharedCombinedKey = (() => {
      const keyPairChallenge = generateRandomKeys()
      const publicKeys = [keyPairChallenge.publicKey, keyPairServer.publicKey]
      const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)

      return combinedPublicKey
    })()

    const keyPairClient = generateRandomKeys()
    const publicNoncesClient = schnorrkelClient.generatePublicNonces(keyPairClient.privateKey)
    const publicNoncesServer = schnorrkelServer.generatePublicNonces(keyPairServer.privateKey)
    const publicNonces = [publicNoncesClient, publicNoncesServer]

    const msg = 'test message'
    const signatureClient = schnorrkelClient.multiSigSign(keyPairClient.privateKey, msg, sharedCombinedKey, publicNonces)

    const combinedPublicKeyServer = Schnorrkel.getCombinedPublicKey([keyPairClient.publicKey, keyPairServer.publicKey])
    const signatureServer = schnorrkelServer.multiSigSign(keyPairServer.privateKey, msg, combinedPublicKeyServer, publicNonces)

    const signatures = [signatureClient.signature, signatureServer.signature]
    const signaturesSummed = Schnorrkel.sumSigs(signatures)
    const result = Schnorrkel.verify(signaturesSummed, msg, signatureServer.finalPublicNonce, combinedPublicKeyServer.combinedKey)

    expect(result).toEqual(false)
  })
})