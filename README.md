<div align="center">

# Schnorr Signatures

*A javaScript library for signing and verifying Schnorr Signatures.*

It can be used for single and multi signatures with and without exposing the public keys individually.

[Requirements](#requirements) |
[Installing](#installing) |
[Examples](#examples) |
[License](#license) |
[Contributing](#contributing)

[![npm version](https://img.shields.io/npm/v/@lorhansohaky/schnorrkel.js.svg?style=flat-square)](https://www.npmjs.org/package/@lorhansohaky/schnorrkel.js)
[![license](https://img.shields.io/github/license/LorhanSohaky/schnorrkel.js.svg?style=flat-square)](https://github.com/LorhanSohaky/schnorrkel.js/blob/main/LICENSE)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/LorhanSohaky/schnorrkel.js/tests.yml?label=tests)
![GitHub issues](https://img.shields.io/github/issues/LorhanSohaky/schnorrkel.js?style=flat-square)

[![npm downloads](https://img.shields.io/npm/dm/@lorhansohaky/schnorrkel.js.svg?style=flat-square)](https://npm-stat.com/charts.html?package=@lorhansohaky/schnorrkel.js)
![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/LorhanSohaky/schnorrkel.js?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/LorhanSohaky/schnorrkel.js?style=flat-square)

</div>

## Requirements:

* Node: >=16.x, <=20.x
* npm (Node.js package manager) v9.x.x

## Installing

### Package manager

```bash
$ npm install @lorhansohaky/schnorrkel.js
```

Using yarn:

```bash
$ yarn add @lorhansohaky/schnorrkel.js
```


### Git
```
git clone https://github.com/LorhanSohaky/schnorrkel.js
cd schnorrkel.js
npm install
```

## Examples

### Single Signatures
We refer to Single Signatures as ones that have a single signer.

Sign:
```ts
import Schnorrkel from '@lorhansohaky/schnorrkel.js/'
import { generateRandomKeys } from '@lorhansohaky/schnorrkel.js/core'

const keyPair = generateRandomKeys()
const privateKey = randomBytes(32) // Buffer
const msg = 'test message'
const {signature, finalPublicNonce} = Schnorrkel.sign(keyPair.privateKey, msg)
```

Offchain verification:
```ts
const publicKey: Uint8Array = ... (derived from the privateKey)
// signature and finalPublicNonce come from s
const result = Schnorrkel.verify(signature, msg, finalPublicNonce, publicKey)
```


You can see the full implementation in `tests/schnorrkel/sign.test.ts` and `tests/schnorrkel/verify.test.ts` in this repository.

### Multisig

Schnorr multisignatures work on the basis n/n - all of the signers need to sign in order for the signature to be valid.
Below are all the steps needed to craft a successful multisig.

#### Public nonces

Public nonces need to be exchanged between signers before they sign. Normally, the Signer should implement this library as define a `getPublicNonces` method that will call the library and return the nonces. For our test example, we're going to call the schnorrkel library directly:

```ts
import Schnorrkel from '@lorhansohaky/schnorrkel.js/'
import { generateRandomKeys } from '@lorhansohaky/schnorrkel.js/core'

const schnorrkel = new Schnorrkel()

const keyPair1 = generateRandomKeys()
const keyPair2 = generateRandomKeys()
const publicNonces1 = schnorrkel.generatePublicNonces(keyPair1.privateKey)
const publicNonces2 = schnorrkel.generatePublicNonces(keyPair2.privateKey)
```

You can see the full implementation in `tests/unsafe-schnorrkel/generatePublicNonces.test.ts` in this repository.

#### sign

After we have them, here is how to sign:

```ts
import Schnorrkel from '@lorhansohaky/schnorrkel.js/'
import { generateRandomKeys } from '@lorhansohaky/schnorrkel.js/core'

const schnorrkelOne = new Schnorrkel()
const schnorrkelTwo = new Schnorrkel()

const keyPairOne = generateRandomKeys()
const keyPairTwo = generateRandomKeys()

const publicNoncesOne = schnorrkelOne.generatePublicNonces(keyPairOne.privateKey)
const publicNoncesTwo = schnorrkelTwo.generatePublicNonces(keyPairTwo.privateKey)

const publicKeys = [keyPair1.publicKey, keyPair2.publicKey]
const publicNonces = [publicNoncesOne, publicNoncesTwo]
const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)

const msg = 'test message'

const signatureOne = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msg, combinedPublicKey, publicNonces)
const signatureTwo = schnorrkelTwo.multiSigSign(keyPairTwo.privateKey, msg, combinedPublicKey, publicNonces)

const signatures = [signatureOne.signature, signatureTwo.signature]
const signaturesSummed = Schnorrkel.sumSigs(signatures)
const result = Schnorrkel.verify(signaturesSummed, msg, signatureTwo.finalPublicNonce, combinedPublicKeyTwo.combinedKey)
```

You can see the full implementation in `tests/schnorrkel/sumSigs.test.ts`, `tests/unsafe-schnorrkel/multiSigSign.test.ts` and `tests/schnorrkel/verify.test.ts` in this repository.
