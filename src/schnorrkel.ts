import secp256k1 from 'secp256k1'

import { Key, Nonces, PublicNonces, Signature, NoncePairs } from './types'

import { _generateL, _aCoefficient, _generatePublicNonces, _multiSigSign, _hashPrivateKey, _sumSigs, _verify, _generatePk, _sign, _generateHashWithSecret, _multiSigSignWithHash } from './core'
import { InternalNonces, InternalPublicNonces } from './core/types'
import { Challenge, FinalPublicNonce, SignatureOutput } from './types/signature'

class Schnorrkel {
  protected nonces: Nonces = {}

  private _setNonce(privateKey: Buffer): string {
    const { publicNonceData, privateNonceData, hash } = _generatePublicNonces(privateKey)

    const mappedPublicNonce: PublicNonces = {
      kPublic: new Key(Buffer.from(publicNonceData.kPublic)),
      kTwoPublic: new Key(Buffer.from(publicNonceData.kTwoPublic)),
    }

    const mappedPrivateNonce: Pick<NoncePairs, 'k' | 'kTwo'> = {
      k: new Key(Buffer.from(privateNonceData.k)),
      kTwo: new Key(Buffer.from(privateNonceData.kTwo))
    }

    this.nonces[hash] = { ...mappedPrivateNonce, ...mappedPublicNonce }
    return hash
  }

  generatePublicNonces(privateKey: Key): PublicNonces {
    const hash = this._setNonce(privateKey.buffer)
    const nonce = this.nonces[hash]

    return {
      kPublic: nonce.kPublic,
      kTwoPublic: nonce.kTwoPublic,
    }
  }

  getPublicNonces(privateKey: Key): PublicNonces {
    const hash = _hashPrivateKey(privateKey.buffer)
    const nonce = this.nonces[hash]

    if (!nonce) {
      throw Error('Nonces not found')
    }

    return {
      kPublic: nonce.kPublic,
      kTwoPublic: nonce.kTwoPublic,
    }
  }

  protected clearNonces(privateKey: Key): void {
    const x = privateKey.buffer
    const hash = _hashPrivateKey(x)

    delete this.nonces[hash]
  }

  static sign(privateKey: Key, msg: string): SignatureOutput {
    const output = _sign(privateKey.buffer, msg)

    return {
      signature: new Signature(Buffer.from(output.signature)),
      finalPublicNonce: new FinalPublicNonce(Buffer.from(output.finalPublicNonce)),
      challenge: new Challenge(Buffer.from(output.challenge)),
    }
  }

  static sumSigs(signatures: Signature[]): Signature {
    const mappedSignatures = signatures.map(signature => signature.buffer)
    const sum = _sumSigs(mappedSignatures)
    return new Signature(Buffer.from(sum))
  }

  static verify(signature: Signature, msg: string, finalPublicNonce: FinalPublicNonce, publicKey: Key): boolean {
    return _verify(signature.buffer, msg, finalPublicNonce.buffer, publicKey.buffer)
  }

  static getCombinedPublicKey(publicKeys: Array<Key>, hexSecret?: string): {
    combinedKey: Key,
    hashedKey: string,
  } {
    if (publicKeys.length < 2) {
      throw Error('At least 2 public keys should be provided')
    }

    const bufferPublicKeys = publicKeys.map(publicKey => publicKey.buffer)
    const hashedKey = _generateHashWithSecret(bufferPublicKeys, hexSecret)

    const modifiedKeys = bufferPublicKeys.map(publicKey => {
      return secp256k1.publicKeyTweakMul(publicKey, _aCoefficient(publicKey, hashedKey))
    })

    return {
      combinedKey: new Key(Buffer.from(secp256k1.publicKeyCombine(modifiedKeys))),
      hashedKey
    }
  }

  multiSigSign(privateKey: Key, msg: string, combinedPublicKey: {
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

  static fromJson(json: string): Schnorrkel {
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

      const schnorrkel = new Schnorrkel()
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

export default Schnorrkel