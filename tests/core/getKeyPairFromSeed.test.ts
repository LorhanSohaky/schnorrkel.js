import { describe, expect, it } from 'vitest'
import argon2 from 'argon2'

import { getKeyPairFromSeed } from '../../src/core'

describe('testing getKeyPairFromSeed', () => {
  it('should get key pair from seed', async () => {
    const seed = 'randomSeed'

    const keyPairOne = getKeyPairFromSeed(seed)
    const keyPairTwo = getKeyPairFromSeed(seed)

    const publicKeyOne = keyPairOne.publicKey.toHex()
    const publicKeyTwo = keyPairTwo.publicKey.toHex()
    const privateKeyOne = keyPairOne.privateKey.toHex()
    const privateKeyTwo = keyPairTwo.privateKey.toHex()

    expect(publicKeyOne).toHaveLength(66)
    expect(privateKeyOne).toHaveLength(64)

    expect(publicKeyOne).toEqual(publicKeyTwo)
    expect(privateKeyOne).toEqual(privateKeyTwo)
  })

  it('should get key pair from argon2 seed', async () => {
    const flag = 'CTF-BR{}'
    const seed = await argon2.hash(flag, {
      salt: Buffer.from('KoVNy6Blq3vFpmdgAXO9MQ==', 'base64'),
      timeCost: 2,
      memoryCost: 2048,
      raw: true
    }).then(buffer => buffer.toString('hex'))

    const keyPairOne = getKeyPairFromSeed(seed)
    const keyPairTwo = getKeyPairFromSeed(seed)

    const publicKeyOne = keyPairOne.publicKey.toHex()
    const publicKeyTwo = keyPairTwo.publicKey.toHex()
    const privateKeyOne = keyPairOne.privateKey.toHex()
    const privateKeyTwo = keyPairTwo.privateKey.toHex()

    expect(publicKeyOne).toHaveLength(66)
    expect(privateKeyOne).toHaveLength(64)

    expect(publicKeyOne).toEqual(publicKeyTwo)
    expect(privateKeyOne).toEqual(privateKeyTwo)
  })
})