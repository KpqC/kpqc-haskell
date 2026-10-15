# KpqC

KpqC provides synchronous Haskell APIs for the AIMer and HAETAE signature
schemes and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs). Native
operations use safe FFI calls so other Haskell threads can continue running.

This Haskell package is independently maintained and is not an official
distribution from the algorithm authors.

## Runtime support

- GHC 8.10 or newer and Cabal 3.4 or newer
- A C11 compiler
- macOS or Linux

The package bundles its native algorithm sources and builds them locally. It
does not download native libraries during compilation.

## Install

Add `KpqC` to your package's dependencies:

```cabal
build-depends: KpqC ^>=0.1.0
```

## Available schemes

- **AIMer** (signature): `AIMer128f`, `AIMer128s`, `AIMer192f`,
  `AIMer192s`, `AIMer256f`, and `AIMer256s`
- **HAETAE** (signature): `HAETAE2`, `HAETAE3`, and `HAETAE5`
- **NTRU+** (KEM): `NTRUPlus768`, `NTRUPlus864`, and `NTRUPlus1152`
- **SMAUG-T** (KEM): `SMAUGT128`, `SMAUGT192`, `SMAUGT256`, and `TiMER`

### Signatures

```haskell
import Crypto.KpqC
import qualified Data.ByteString.Char8 as BS

main :: IO ()
main = do
  Right keys <- generateKeyPair AIMer128f
  let message = BS.pack "release-manifest:v3"
  Right signature <- sign AIMer128f message (secretKey keys)
  Right True <- verify AIMer128f message signature (publicKey keys)
  pure ()
```

`signWithContext` and `verifyWithContext` accept a domain-separation context
of at most 255 bytes. Verification fails when the supplied context differs
from the signing context.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```haskell
import Crypto.KpqC

main :: IO ()
main = do
  Right recipient <- generateKeyPair SMAUGT192
  Right outbound <- encapsulate SMAUGT192 (publicKey recipient)
  Right inbound <-
    decapsulate SMAUGT192 (ciphertext outbound) (secretKey recipient)
  print (inbound == sharedSecret outbound)
```

## Data and failures

Public keys, signatures, ciphertexts, messages, and contexts are strict
`ByteString` values. Secret keys and shared secrets use `SecretBytes`, backed
by `ScrubbedBytes` so their memory is scrubbed when it is no longer referenced
and equality checks are constant-time. Signing and decapsulation also accept
other `ByteArrayAccess` types, including strict `ByteString`. Operations return
`IO (Either KpqCError value)`. Invalid signatures return `Right False`.

NTRU+ rejects non-canonical public keys and invalid ciphertexts. SMAUG-T uses
implicit rejection and returns a replacement secret for an invalid
ciphertext; it will not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

- `AIMer128f`: public key 32; secret key 48; signature 6,944
- `AIMer128s`: public key 32; secret key 48; signature 4,704
- `AIMer192f`: public key 48; secret key 72; signature 15,408
- `AIMer192s`: public key 48; secret key 72; signature 10,320
- `AIMer256f`: public key 64; secret key 96; signature 31,360
- `AIMer256s`: public key 64; secret key 96; signature 20,224
- `HAETAE2`: public key 992; secret key 1,408; signature 1,474
- `HAETAE3`: public key 1,472; secret key 2,112; signature 2,349
- `HAETAE5`: public key 2,080; secret key 2,752; signature 2,948

#### KEMs

- `NTRUPlus768`: public key 1,152; secret key 2,336; ciphertext 1,152;
  shared secret 32
- `NTRUPlus864`: public key 1,296; secret key 2,624; ciphertext 1,296;
  shared secret 32
- `NTRUPlus1152`: public key 1,728; secret key 3,488; ciphertext 1,728;
  shared secret 32
- `SMAUGT128`: public key 672; secret key 832; ciphertext 672; shared
  secret 32
- `SMAUGT192`: public key 1,088; secret key 1,312; ciphertext 992; shared
  secret 32
- `SMAUGT256`: public key 1,440; secret key 1,728; ciphertext 1,376; shared
  secret 32
- `TiMER`: public key 672; secret key 832; ciphertext 608; shared secret 32

## Tests

```sh
cabal test spec
```

The optional known-answer suite validates all 1,600 records from the pinned
[KpqC/kpqc-test-vectors at commit d75490bf824f](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da):

```sh
cabal clean
KPQC_TEST_VECTORS=../kpqc-test-vectors cabal test kat -fkat --enable-tests
```

Deterministic entropy hooks are compiled only when the manual `kat` flag is
enabled. Run the suite from a clean build so Cabal recompiles the bundled C
sources with those hooks enabled.

## Security

The native cores are compiled from the upstream reference implementations.
This package has not received an independent security audit and does not
guarantee constant-time execution. Assess those constraints before using it
with sensitive production keys.

Algorithm encodings and parameter sizes follow the exact upstream revisions
listed below and may differ from other revisions of the same algorithms.

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](https://github.com/KpqC/kpqc-haskell/blob/main/THIRD_PARTY_NOTICES.md).
