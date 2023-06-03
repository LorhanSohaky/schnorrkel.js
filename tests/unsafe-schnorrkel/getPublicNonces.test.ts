import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing getPublicNonces', () => {
  it('should generate public nonces', () => {
    const schnorrkel = new Schnorrkel()

    const keyPair = generateRandomKeys()
    schnorrkel.generatePublicNonces(keyPair.privateKey)
    const publicNonces = schnorrkel.getPublicNonces(keyPair.privateKey)

    expect(publicNonces).toBeDefined()
    expect(publicNonces.kPublic).toBeDefined()
    expect(publicNonces.kTwoPublic).toBeDefined()
    expect(publicNonces.kPublic.buffer).toHaveLength(33)
    expect(publicNonces.kTwoPublic.buffer).toHaveLength(33)
  })

  it('should throw error if public nonces are not generated', () => {
    const schnorrkel = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    schnorrkel.generatePublicNonces(keyPairOne.privateKey)
    expect(() => schnorrkel.getPublicNonces(keyPairTwo.privateKey)).toThrowError('Nonces not found')
  })
})