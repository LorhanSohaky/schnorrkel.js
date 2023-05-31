import secp256k1 from 'secp256k1'

import { Challenge, FinalPublicNonce, Key, PublicNonces, Signature, SignatureOutput } from './types'

import { _generateL, _aCoefficient, _generatePublicNonces, _multiSigSign, _hashPrivateKey, _sumSigs, _verify, _generatePk, _sign, _generateHashWithSalt, _multiSigSignWithHash } from './core'
import Schnorrkel from './schnorrkel'
import { InternalNonces, InternalPublicNonces } from './core/types'

class UnsafeSchnorrkel extends Schnorrkel {
  static generateCombinedPublicKeyWithSalt(publicKeys: Array<Key>): {
    combinedKey: Key,
    hashedKey: string,
  } {
    if (publicKeys.length < 2) {
      throw Error('At least 2 public keys should be provided')
    }

    const bufferPublicKeys = publicKeys.map(publicKey => publicKey.buffer)
    const hashedKey = _generateHashWithSalt(bufferPublicKeys)

    const modifiedKeys = bufferPublicKeys.map(publicKey => {
      return secp256k1.publicKeyTweakMul(publicKey, _aCoefficient(publicKey, hashedKey))
    })

    return {
      combinedKey: new Key(Buffer.from(secp256k1.publicKeyCombine(modifiedKeys))),
      hashedKey
    }
  }

  multiSigSignWithHash(privateKey: Key, msg: string, combinedPublicKey: {
    combinedKey: Key,
    hashedKey: string
  }, publicNonces: PublicNonces[]): SignatureOutput {
    const mappedPublicNonce: InternalPublicNonces[] = publicNonces.map(publicNonce => {
      return {
        kPublic: publicNonce.kPublic.buffer,
        kTwoPublic: publicNonce.kTwoPublic.buffer,
      }
    })

    const mappedNonces: InternalNonces = Object.fromEntries(Object.entries(this.nonces).map(([hash, nonce]) => {
      return [
        hash,
        {
          k: nonce.k.buffer,
          kTwo: nonce.kTwo.buffer,
          kPublic: nonce.kPublic.buffer,
          kTwoPublic: nonce.kTwoPublic.buffer,
        }
      ]
    }))

    const musigData = _multiSigSignWithHash(mappedNonces, combinedPublicKey.combinedKey.buffer, combinedPublicKey.hashedKey, privateKey.buffer, msg, mappedPublicNonce)

    // absolutely crucial to delete the nonces once a signature has been crafted with them.
    // nonce reusae will lead to private key leakage!
    this.clearNonces(privateKey)

    return {
      signature: new Signature(Buffer.from(musigData.signature)),
      finalPublicNonce: new FinalPublicNonce(Buffer.from(musigData.finalPublicNonce)),
      challenge: new Challenge(Buffer.from(musigData.challenge)),
    }
  }

  static fromJson(json: string): UnsafeSchnorrkel {
    interface JsonData {
      nonces: {
        [hash: string]: {
          k: string,
          kTwo: string,
          kPublic: string,
          kTwoPublic: string,
        }
      }
    }
    try {
      const jsonData = JSON.parse(json) as JsonData
      const noncesEntries = Object.entries(jsonData.nonces).map(([hash, nonce]) => {
        return [
          hash,
          {
            k: Key.fromHex(nonce.k),
            kTwo: Key.fromHex(nonce.kTwo),
            kPublic: Key.fromHex(nonce.kPublic),
            kTwoPublic: Key.fromHex(nonce.kTwoPublic),
          }
        ]
      })

      const schnorrkel = new UnsafeSchnorrkel()
      schnorrkel.nonces = Object.fromEntries(noncesEntries)
      return schnorrkel
    } catch (error) {
      throw new Error('Invalid JSON')
    }
  }

  toJson() {
    const nonces = Object.fromEntries(Object.entries(this.nonces).map(([hash, nonce]) => {
      return [
        hash,
        {
          k: nonce.k.toHex(),
          kTwo: nonce.kTwo.toHex(),
          kPublic: nonce.kPublic.toHex(),
          kTwoPublic: nonce.kTwoPublic.toHex(),
        }
      ]
    }))

    return JSON.stringify({
      nonces,
    })
  }
}

export default UnsafeSchnorrkel