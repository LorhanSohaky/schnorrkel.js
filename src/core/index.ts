import { randomBytes } from 'crypto'
import { ethers } from 'ethers'
import secp256k1 from 'secp256k1'
import ecurve from 'ecurve'
import elliptic from 'elliptic'
import bigi from 'bigi'
import { BN } from 'bn.js'

import { InternalNoncePairs, InternalNonces, InternalPublicNonces, InternalSignature } from './types'
import { KeyPair } from '../types'

const curve = ecurve.getCurveByName('secp256k1')
const n = curve?.n
const EC = elliptic.ec
const ec = new EC('secp256k1')
const generatorPoint = ec.g

export const _generateHashWithSecret = (publicKeys: ReadonlyArray<Buffer>, hexSecret?: string) => {
  let internalPublicKeys = publicKeys.slice()

  if (typeof hexSecret === 'string') {
    if (hexSecret.length === 0) {
      throw new Error('Secret cannot be empty')
    }

    const regexHex = /^[0-9A-Fa-f]+$/g;

    if (!hexSecret.match(regexHex)) {
      throw new Error('Secret should be a hex string')
    }

    const secretUint8Array = Buffer.from(Uint8Array.from(Buffer.from(hexSecret, 'hex')))
    if (secretUint8Array.length > 33) {
      throw new Error('Secret should be 33 bytes or less')
    }

    internalPublicKeys = [...internalPublicKeys, secretUint8Array]
  }

  return ethers.utils.keccak256(_concatTypedArrays(internalPublicKeys.sort(Buffer.compare)))
}

export const _concatTypedArrays = (publicKeys: ReadonlyArray<Buffer>): Buffer => {
  const c: Buffer = Buffer.alloc(publicKeys.reduce((partialSum, publicKey) => partialSum + publicKey.length, 0))
  publicKeys.map((publicKey, index) => c.set(publicKey, (index * publicKey.length)))
  return Buffer.from(c.buffer)
}


export const _aCoefficient = (publicKey: Buffer, L: string): Buffer => {
  const coefficient = ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes'],
    [L, publicKey]
  ))

  return Buffer.from(coefficient)
}

const _bCoefficient = (combinedPublicKey: Buffer, msgHash: string, publicNonces: ReadonlyArray<InternalPublicNonces>): Buffer => {
  type KeyOf = keyof InternalPublicNonces
  const arrayColumn = (arr: ReadonlyArray<InternalPublicNonces>, n: KeyOf) => arr.map(x => x[n])
  const kPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kPublic'))
  const kTwoPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kTwoPublic'))

  const bCoefficient = ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes32', 'bytes', 'bytes'],
    [combinedPublicKey, msgHash, kPublicNonces, kTwoPublicNonces]
  ))

  return Buffer.from(bCoefficient)
}

const _generateRandomPrivateKey = () => {
  let privKeyBytes: Buffer | undefined
  do {
    privKeyBytes = randomBytes(32)
  } while (!secp256k1.privateKeyVerify(privKeyBytes))

  return privKeyBytes
}

export const generateRandomKeys = (): KeyPair => {
  const privKeyBytes = _generateRandomPrivateKey()
  const pubKey = Buffer.from(secp256k1.publicKeyCreate(privKeyBytes))

  const data = {
    publicKey: pubKey,
    privateKey: privKeyBytes,
  }

  return new KeyPair(data)
}

export const generateRandomSecret = () => {
  return generateRandomKeys().publicKey.toHex()
}

export const getKeyPairFromSeed = (seed: string) => {
  let privKeyBytes: Buffer | undefined
  let round = 0
  do {
    const seedUint8 = Uint8Array.from(Buffer.from(seed, 'hex'))
    const iUint8 = Uint8Array.from(Buffer.from(round.toString(), 'hex'))
    const mergedBuffer = Buffer.from(mergeUint8Arrays(seedUint8, iUint8))
    const hash = ethers.utils.keccak256(mergedBuffer)
    privKeyBytes = Buffer.from(hash.replace(/^0x/, ''), 'hex')
    round++
  } while (!secp256k1.privateKeyVerify(privKeyBytes))

  const pubKey = Buffer.from(secp256k1.publicKeyCreate(privKeyBytes))

  const data = {
    publicKey: pubKey,
    privateKey: privKeyBytes,
  }

  return new KeyPair(data)
}

const mergeUint8Arrays = (...arrays: ReadonlyArray<Uint8Array>): Uint8Array => {
  const totalSize = arrays.reduce((acc, e) => acc + e.length, 0)
  const merged = new Uint8Array(totalSize)

  arrays.forEach((array, i, arrays) => {
    const offset = arrays.slice(0, i).reduce((acc, e) => acc + e.length, 0)
    merged.set(array, offset)
  });

  return merged
}

export const _hashPrivateKey = (privateKey: Buffer): string => {
  return ethers.utils.keccak256(privateKey)
}

export const _generatePublicNonces = (privateKey: Buffer): {
  privateNonceData: Pick<InternalNoncePairs, 'k' | 'kTwo'>,
  publicNonceData: InternalPublicNonces,
  hash: string,
} => {
  const hash = _hashPrivateKey(privateKey)
  const nonce = _generateNonce()

  return {
    hash,
    privateNonceData: {
      k: nonce.k,
      kTwo: nonce.kTwo,
    },
    publicNonceData: {
      kPublic: nonce.kPublic,
      kTwoPublic: nonce.kTwoPublic,
    }
  }
}

const _generateNonce = (): InternalNoncePairs => {
  const k = Buffer.from(ethers.utils.randomBytes(32))
  const kTwo = Buffer.from(ethers.utils.randomBytes(32))
  const kPublic = Buffer.from(secp256k1.publicKeyCreate(k))
  const kTwoPublic = Buffer.from(secp256k1.publicKeyCreate(kTwo))

  return {
    k,
    kTwo,
    kPublic,
    kTwoPublic,
  }
}

export const _multiSigSign = (nonces: InternalNonces, combinedPublicKey: Buffer, privateKey: Buffer, msg: string, publicKeys: ReadonlyArray<Buffer>, publicNonces: ReadonlyArray<InternalPublicNonces>): InternalSignature => {
  if (publicKeys.length < 2) {
    throw Error('At least 2 public keys should be provided')
  }

  const localPk = Buffer.from(privateKey)
  const xHashed = _hashPrivateKey(localPk)
  if (!(xHashed in nonces) || Object.keys(nonces[xHashed]).length === 0) {
    throw Error('Nonces should be exchanged before signing')
  }

  const publicKey = Buffer.from(secp256k1.publicKeyCreate(localPk))
  const L = _generateHashWithSecret(publicKeys)
  const msgHash = _hashMessage(msg)
  const a = _aCoefficient(publicKey, L)
  const b = _bCoefficient(combinedPublicKey, msgHash, publicNonces)

  const effectiveNonces = publicNonces.map((batch) => {
    return Buffer.from(secp256k1.publicKeyCombine([batch.kPublic, secp256k1.publicKeyTweakMul(batch.kTwoPublic, b)]))
  })
  const signerEffectiveNonce = Buffer.from(secp256k1.publicKeyCombine([
    nonces[xHashed].kPublic,
    secp256k1.publicKeyTweakMul(nonces[xHashed].kTwoPublic, b)
  ]))
  const inArray = effectiveNonces.filter(nonce => areBuffersSame(nonce, signerEffectiveNonce)).length != 0
  if (!inArray) {
    throw Error('Passed nonces are invalid')
  }

  const R = Buffer.from(secp256k1.publicKeyCombine(effectiveNonces))
  const e = challenge(R, msgHash, combinedPublicKey)

  const { k, kTwo } = nonces[xHashed]

  // xe = x * e
  const xe = secp256k1.privateKeyTweakMul(localPk, e)

  // xea = a * xe
  const xea = secp256k1.privateKeyTweakMul(xe, a)

  // k + xea
  const kPlusxea = secp256k1.privateKeyTweakAdd(xea, k)

  // kTwo * b
  const kTwoMulB = secp256k1.privateKeyTweakMul(kTwo, b)

  // k + kTwoMulB + xea
  const final = secp256k1.privateKeyTweakAdd(kPlusxea, kTwoMulB)

  // s = k + xea mod(n)
  const signature = Buffer.from(bigi.fromBuffer(final).mod(n).toBuffer(32))

  return {
    signature,
    challenge: e,
    finalPublicNonce: R
  }
}

export const _multiSigSignWithHash = (nonces: InternalNonces, combinedPublicKey: Buffer, hashedCombinedPublicKeys: string, privateKey: Buffer, msg: string, publicNonces: ReadonlyArray<InternalPublicNonces>): InternalSignature => {
  const localPk = Buffer.from(privateKey)
  const xHashed = _hashPrivateKey(localPk)
  if (!(xHashed in nonces) || Object.keys(nonces[xHashed]).length === 0) {
    throw Error('Nonces should be exchanged before signing')
  }

  const publicKey = Buffer.from(secp256k1.publicKeyCreate(localPk))
  const L = hashedCombinedPublicKeys
  const msgHash = _hashMessage(msg)
  const a = _aCoefficient(publicKey, L)
  const b = _bCoefficient(combinedPublicKey, msgHash, publicNonces)

  const effectiveNonces = publicNonces.map((batch) => {
    return Buffer.from(secp256k1.publicKeyCombine([batch.kPublic, secp256k1.publicKeyTweakMul(batch.kTwoPublic, b)]))
  })
  const signerEffectiveNonce = Buffer.from(secp256k1.publicKeyCombine([
    nonces[xHashed].kPublic,
    secp256k1.publicKeyTweakMul(nonces[xHashed].kTwoPublic, b)
  ]))
  const inArray = effectiveNonces.filter(nonce => areBuffersSame(nonce, signerEffectiveNonce)).length != 0
  if (!inArray) {
    throw Error('Passed nonces are invalid')
  }

  const R = Buffer.from(secp256k1.publicKeyCombine(effectiveNonces))
  const e = challenge(R, msgHash, combinedPublicKey)

  const { k, kTwo } = nonces[xHashed]

  // xe = x * e
  const xe = secp256k1.privateKeyTweakMul(localPk, e)

  // xea = a * xe
  const xea = secp256k1.privateKeyTweakMul(xe, a)

  // k + xea
  const kPlusxea = secp256k1.privateKeyTweakAdd(xea, k)

  // kTwo * b
  const kTwoMulB = secp256k1.privateKeyTweakMul(kTwo, b)

  // k + kTwoMulB + xea
  const final = secp256k1.privateKeyTweakAdd(kPlusxea, kTwoMulB)


  // s = k + xea mod(n)
  const signature = bigi.fromBuffer(final).mod(n).toBuffer(32)
  return {
    signature,
    challenge: e,
    finalPublicNonce: R
  }
}

const areBuffersSame = (buf1: Buffer, buf2: Buffer): boolean => {
  if (buf1.byteLength != buf2.byteLength) return false

  var dv1 = Buffer.from(buf1)
  var dv2 = Buffer.from(buf2)
  for (var i = 0; i != buf1.byteLength; i++) {
    if (dv1[i] != dv2[i]) return false
  }

  return true
}

const challenge = (R: Buffer, msgHash: string, publicKey: Buffer): Buffer => {
  // convert R to address
  var R_uncomp = secp256k1.publicKeyConvert(R, false)
  var R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32)

  // e = keccak256(address(R) || compressed publicKey || msgHash)
  const e = ethers.utils.arrayify(
    ethers.utils.solidityKeccak256(
      ['address', 'uint8', 'bytes32', 'bytes32'],
      [R_addr, publicKey[0] + 27 - 2, Uint8Array.from(publicKey).slice(1, 33), msgHash]
    )
  )

  return Buffer.from(e)
}

export const _sumSigs = (signatures: Buffer[]): Buffer => {
  let combined = bigi.fromBuffer(signatures[0])
  signatures.shift()
  signatures.forEach(sig => {
    combined = combined.add(bigi.fromBuffer(sig))
  })
  return combined.mod(n).toBuffer(32)
}

export const _hashMessage = (message: string): string => {
  return ethers.utils.solidityKeccak256(['string'], [message])
}

export const _verify = (s: Buffer, msg: string, R: Buffer, publicKey: Buffer): boolean => {
  const hash = _hashMessage(msg)
  const eC = challenge(R, hash, publicKey)
  const sG = generatorPoint.mul(ethers.utils.arrayify(s))
  const P = ec.keyFromPublic(publicKey).getPublic()
  const bnEC = new BN(Buffer.from(eC).toString('hex'), 'hex')
  const Pe = P.mul(bnEC)
  const toPublicR = ec.keyFromPublic(R).getPublic()
  const RplusPe = toPublicR.add(Pe)
  return sG.eq(RplusPe)
}

export const _sign = (privateKey: Buffer, msg: string): InternalSignature => {
  const localPk = Buffer.from(privateKey)
  const publicKey = Buffer.from(secp256k1.publicKeyCreate((localPk as any)))

  const hash = _hashMessage(msg)

  // R = G * k
  var k = ethers.utils.randomBytes(32)
  var R = Buffer.from(secp256k1.publicKeyCreate(k))

  // e = h(address(R) || compressed pubkey || m)
  var e = challenge(R, hash, publicKey)

  // xe = x * e
  var xe = secp256k1.privateKeyTweakMul((localPk as any), e)

  // s = k + xe
  var s = Buffer.from(secp256k1.privateKeyTweakAdd(k, xe))

  return {
    finalPublicNonce: R,
    challenge: e,
    signature: s
  }
}

export const signProof = (msg: Buffer, privateKey: Buffer): Buffer => {
  const output = secp256k1.ecdsaSign(msg, privateKey)
  return Buffer.from(output.signature)
}

export const verifyProof = (msg: Buffer, signature: Buffer, publicKey: Buffer): boolean => {
  return secp256k1.ecdsaVerify(signature, msg, publicKey)
}