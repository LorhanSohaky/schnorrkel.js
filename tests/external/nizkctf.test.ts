import { describe, expect, it, beforeEach } from 'vitest'
import { randomBytes, createHash } from 'node:crypto'
import argon2 from 'argon2'

import Schnorrkel, { Key, KeyPair, PublicNonces } from '../../src/index'
import { _hashPrivateKey, generateRandomKeys, getKeyPairFromSeed, _hashMessage, signProof, verifyProof } from '../../src/core'

let challengeKeyPair: KeyPair
type CombinedPublicKey = ReturnType<typeof Schnorrkel.getCombinedPublicKey>
let combinedPublicKey: CombinedPublicKey
let serverKeyPair: KeyPair

const SERVER_SECRET = 'F06AD1A665931A843D2345D49186471969B15DE3F5FA8DB3297D64BAC5C4898F'
const TEAM_ID = 'a3fda20d-03a3-43ee-8fa8-ead1cba9316d'

const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')

let kvDb: {
  [sessionId: string]: {
    client: {
      publicKey: string
      publicNonce: {
        kPublic: string
        kTwoPublic: string
      }
    }
    server: {
      state: string
    }
  }
}

describe('testing nizkctf', () => {
  beforeEach(() => {
    serverKeyPair = KeyPair.fromJson(JSON.stringify({
      publicKey: '03288edfd036a3104d76d838d25eff0a42198627385f632b626bdb58c33e7c3533',
      privateKey: 'fe09c6e1154b5d46579f4785a63a3b7aeae834cbbeadb935af7aaebcc51e93d1'
    }))

    // simulate the challenge key pair generated from seed like CTF-BR{123}
    challengeKeyPair = generateRandomKeys()
    const publicKeys = [challengeKeyPair.publicKey, serverKeyPair.publicKey]

    combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys, SERVER_SECRET)


    // reset key-value database
    kvDb = {}
  })

  it('should generate key pair for the challenge', async () => {
    const flag = 'CTF-BR{123}'
    const salt = Buffer.from('KoVNy6Blq3vFpmdgAXO9MQ==','base64')
    const seed = await argon2.hash(flag, {
      salt,
      timeCost: 2,
      memoryCost: 2048,
      raw:true
    }).then(buffer => buffer.toString('hex'))

    const challengeKeyPair = getKeyPairFromSeed(seed)

    const  { combinedKey, hashedKey } = Schnorrkel.getCombinedPublicKey([challengeKeyPair.publicKey, serverKeyPair.publicKey], SERVER_SECRET)

    expect(combinedKey).toBeDefined()
    expect(combinedKey).toBeInstanceOf(Key)
    expect(combinedKey.toHex()).toEqual('025b56467c55e1a83099d4f8b08767a0faf16a4ad05622386b2224278a81803cb9')
    expect(hashedKey).toBeDefined()
    expect(hashedKey).toEqual('0x5e27c3617a7739248fa27f2c6f47955a737c77b92ce8ea7993a5027411fab8a8')
  })

  it('should create a proof of knowledge of the secret key', async () => {
    const flag = 'CTF-BR{123}'
    const salt = Buffer.from('KoVNy6Blq3vFpmdgAXO9MQ==','base64')
    const seed = await argon2.hash(flag, {
      salt,
      timeCost: 2,
      memoryCost: 2048,
      raw:true
    }).then(buffer => buffer.toString('hex'))

    const challengeKeyPair = getKeyPairFromSeed(seed)

    const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')
    
    const teamHash = sha256(TEAM_ID)
    const proof = signProof(Buffer.from(teamHash, 'hex'), challengeKeyPair.privateKey.buffer)
    const proofHex = proof.toString('hex')
    expect(proofHex).toBeDefined()
    expect(proofHex).toHaveLength(128)
    expect(proofHex).toEqual('8aa4d0664857ef7821cbc5262212e1d1270b35c81e5de20b94183985eb27c97344a5b3fc362a02902ffa580043d35258035ffb1e925381c57a5da23ca99b8bc4')
  })

  it('should verify the proof of knowledge of the secret key', async () => {
    const flag = 'CTF-BR{123}'
    const salt = Buffer.from('KoVNy6Blq3vFpmdgAXO9MQ==','base64')
    const seed = await argon2.hash(flag, {
      salt,
      timeCost: 2,
      memoryCost: 2048,
      raw:true
    }).then(buffer => buffer.toString('hex'))

    const challengeKeyPair = getKeyPairFromSeed(seed)
    
    const teamHash = sha256(TEAM_ID)
    const proof = signProof(Buffer.from(teamHash, 'hex'), challengeKeyPair.privateKey.buffer)
    
    const result = verifyProof(Buffer.from(teamHash, 'hex'), proof, challengeKeyPair.publicKey.buffer)
    expect(result).toBeTruthy()
  })

  it('should fail to verify the proof of knowledge of the secret key', async () => {
    const flag = 'CTF-BR{123}'
    const salt = Buffer.from('KoVNy6Blq3vFpmdgAXO9MQ==','base64')
    const seed = await argon2.hash(flag, {
      salt,
      timeCost: 2,
      memoryCost: 2048,
      raw:true
    }).then(buffer => buffer.toString('hex'))

    const challengeKeyPair = getKeyPairFromSeed(seed)
    const otherKeyPair = generateRandomKeys()

    const sha256 = (data: string) => createHash('sha256').update(data).digest('hex')
    
    const teamHash = sha256(TEAM_ID)
    const invalidProof = signProof(Buffer.from(teamHash, 'hex'), otherKeyPair.privateKey.buffer)
    
    const result = verifyProof(Buffer.from(teamHash, 'hex'), invalidProof, challengeKeyPair.publicKey.buffer)
    expect(result).toBeFalsy()
  })

  it('should verify signatures', () => {
    const schnorrkelClient = new Schnorrkel()
    let schnorrkelServer = new Schnorrkel()

    // 1. Client generates a key pair from seed

    //simulate the challenge key pair generated from seed like CTF-BR{123}
    const clientKeyPair = KeyPair.fromJson(challengeKeyPair.toJson())
    const clientPublicNonce = schnorrkelClient.generatePublicNonces(clientKeyPair.privateKey)

    // 2. Client sends the public nonce and public key to the server
    // server stores the public nonce and public key in a database
    const session = randomBytes(128).toString('hex')

    const serverPublicNonce = schnorrkelServer.generatePublicNonces(serverKeyPair.privateKey)

    kvDb[session] = {
      client: {
        publicKey: clientKeyPair.publicKey.toHex(),
        publicNonce: {
          kPublic: clientPublicNonce.kPublic.toHex(),
          kTwoPublic: clientPublicNonce.kTwoPublic.toHex(),
        },
      },
      server: {
        state: schnorrkelServer.toJson()
      }
    }

    // 3. Server sends the public nonce to the client,
    // so the client generates a signature using the combined public key shared at the beginning of the challenge
    // and sends it to the server with session id and msg
    const clientPublicNonces = [clientPublicNonce, serverPublicNonce]
    const msg = sha256(TEAM_ID)

    const clientSignature = schnorrkelClient.multiSigSign(clientKeyPair.privateKey, msg, combinedPublicKey, clientPublicNonces)

    // 4. Server receives the signature and verifies it
    const prevState = kvDb[session]
    schnorrkelServer = Schnorrkel.fromJson(prevState.server.state)
    const serverPrevPublicNonce = schnorrkelServer.getPublicNonces(serverKeyPair.privateKey)
    const serverPublicNonces: ReadonlyArray<PublicNonces> = [serverPrevPublicNonce, {
      kPublic: Key.fromHex(prevState.client.publicNonce.kPublic),
      kTwoPublic: Key.fromHex(prevState.client.publicNonce.kTwoPublic),
    }]
    const serverSignature = schnorrkelServer.multiSigSign(serverKeyPair.privateKey, msg, combinedPublicKey, serverPublicNonces)
    const signatures = [clientSignature.signature, serverSignature.signature]
    const signaturesSummed = Schnorrkel.sumSigs(signatures)
    const result = Schnorrkel.verify(signaturesSummed, msg, serverSignature.finalPublicNonce, combinedPublicKey.combinedKey)

    delete kvDb[session]

    expect(result).toEqual(true)
    expect(kvDb).toEqual({})
    })
})