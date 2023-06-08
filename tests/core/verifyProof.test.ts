import { describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'

import { signProof, generateRandomKeys, verifyProof } from '../../src/core'

const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')

describe('testing verifyProof', () => {
  it('should verify the proof', async () => {
    const keyPair = generateRandomKeys()

    const msg = sha256('msg example')
    const proof = signProof(Buffer.from(msg, 'hex'), keyPair.privateKey.buffer)

    const result = verifyProof(Buffer.from(msg, 'hex'), proof, keyPair.publicKey.buffer)
    expect(result).toBeTruthy()
  })

  it('should fail to verify the proof of knowledge of the secret key', async () => {
    const keyPairOne = generateRandomKeys()
    const otherKeyPair = generateRandomKeys()

    const msg = sha256('msg example')
    const invalidProof = signProof(Buffer.from(msg, 'hex'), otherKeyPair.privateKey.buffer)
    
    const result = verifyProof(Buffer.from(msg, 'hex'), invalidProof, keyPairOne.publicKey.buffer)
    expect(result).toBeFalsy()
  })
})