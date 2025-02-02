import { describe, expect, it } from 'vitest'

import { _generateHashWithSecret } from '../../src/core'

describe('testing _generateHashWithSecret', () => {
  it('should get the expected hash for L even if public keys switch places (test if sorting works correctly)', () => {
    const publicKeyOne = Buffer.from('02e823a040a5602776959fe78ce3e1856dd1f9ae3a113da602854c98bd67fafd8f', 'hex')
    const publicKeyTwo = Buffer.from('02946ef03de338aed83037c2d344114c64f5cef75ffc498b0854dabdb98a3a8fc9', 'hex');

    const lHash = _generateHashWithSecret([publicKeyOne, publicKeyTwo])
    const lHashSorted = _generateHashWithSecret([publicKeyTwo, publicKeyOne])

    expect(lHash).toEqual('0x5862551eb4dc671b6127b8234ce5eb443b55dc4f334566a7a9e7e5c17ee6bd92')
    expect(lHashSorted).toEqual('0x5862551eb4dc671b6127b8234ce5eb443b55dc4f334566a7a9e7e5c17ee6bd92')
  })
})