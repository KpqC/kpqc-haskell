# KpqC

KpqC provides synchronous Haskell APIs for AIMer, HAETAE, NTRU+, and
SMAUG-T. Native operations use safe FFI calls so other Haskell threads can
continue running.

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

| Algorithm | Type | Constructors |
| --- | --- | --- |
| **AIMer** | Signature | `AIMer128f`, `AIMer128s`, `AIMer192f`, `AIMer192s`, `AIMer256f`, `AIMer256s` |
| **HAETAE** | Signature | `HAETAE2`, `HAETAE3`, `HAETAE5` |
| **NTRU+** | Key encapsulation | `NTRUPlus768`, `NTRUPlus864`, `NTRUPlus1152` |
| **SMAUG&#8209;T** | Key encapsulation | `SMAUGT128`, `SMAUGT192`, `SMAUGT256`, `TiMER` |

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

### Key encapsulation

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

| Constructor | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `AIMer128f` | 32 | 48 | 6,944 |
| `AIMer128s` | 32 | 48 | 4,704 |
| `AIMer192f` | 48 | 72 | 15,408 |
| `AIMer192s` | 48 | 72 | 10,320 |
| `AIMer256f` | 64 | 96 | 31,360 |
| `AIMer256s` | 64 | 96 | 20,224 |
| `HAETAE2` | 992 | 1,408 | 1,474 |
| `HAETAE3` | 1,472 | 2,112 | 2,349 |
| `HAETAE5` | 2,080 | 2,752 | 2,948 |

#### Key encapsulation

| Constructor | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `NTRUPlus768` | 1,152 | 2,336 | 1,152 | 32 |
| `NTRUPlus864` | 1,296 | 2,624 | 1,296 | 32 |
| `NTRUPlus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `SMAUGT128` | 672 | 832 | 672 | 32 |
| `SMAUGT192` | 1,088 | 1,312 | 992 | 32 |
| `SMAUGT256` | 1,440 | 1,728 | 1,376 | 32 |
| `TiMER` | 672 | 832 | 608 | 32 |

## Tests

```sh
cabal test spec
```

The optional known-answer suite validates all 1,600 records from the pinned
[`kpqc-test-vectors` revision](https://github.com/KpqC/kpqc-test-vectors/tree/179dcc05ece2e22262cea1a61f3cdf1a5b08a304):

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
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
