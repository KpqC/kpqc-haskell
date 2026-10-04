-- | Synchronous bindings for the KpqC post-quantum algorithms.
module Crypto.KpqC
  ( Algorithm (..),
    SignatureAlgorithm (..),
    KEMAlgorithm (..),
    SignatureSizes (..),
    KEMSizes (..),
    SecretBytes,
    KeyPair (..),
    EncapsulatedSecret (..),
    Operation (..),
    KpqCError (..),
    signatureAlgorithms,
    kemAlgorithms,
    signatureSizes,
    kemSizes,
    sign,
    signWithContext,
    verify,
    verifyWithContext,
    encapsulate,
    decapsulate
  )
where

import Control.Exception (finally)
import Control.Monad (when)
import qualified Crypto.KpqC.Internal.Native.AIMer as AIMer
import qualified Crypto.KpqC.Internal.Native.HAETAE as HAETAE
import qualified Crypto.KpqC.Internal.Native.NTRUPlus as NTRUPlus
import qualified Crypto.KpqC.Internal.Native.SMAUGT as SMAUGT
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteArray as BA
import Data.Word (Word8, Word64)
import Foreign.C.Types (CInt, CSize)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (allocaArray)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peek, poke)

-- | A detached-signature parameter set.
data SignatureAlgorithm
  = AIMer128f
  | AIMer128s
  | AIMer192f
  | AIMer192s
  | AIMer256f
  | AIMer256s
  | HAETAE2
  | HAETAE3
  | HAETAE5
  deriving (Bounded, Enum, Eq, Ord, Read, Show)

-- | A key-encapsulation parameter set.
data KEMAlgorithm
  = NTRUPlus768
  | NTRUPlus864
  | NTRUPlus1152
  | SMAUGT128
  | SMAUGT192
  | SMAUGT256
  | TiMER
  deriving (Bounded, Enum, Eq, Ord, Read, Show)

-- | Fixed byte lengths for a signature parameter set.
data SignatureSizes = SignatureSizes
  { signaturePublicKeyBytes :: !Int,
    signatureSecretKeyBytes :: !Int,
    signatureBytes :: !Int
  }
  deriving (Eq, Show)

-- | Fixed byte lengths for a key-encapsulation parameter set.
data KEMSizes = KEMSizes
  { kemPublicKeyBytes :: !Int,
    kemSecretKeyBytes :: !Int,
    ciphertextBytes :: !Int,
    sharedSecretBytes :: !Int
  }
  deriving (Eq, Show)

-- | Secret material backed by memory that is scrubbed when no longer
-- referenced and compared in constant time.
type SecretBytes = BA.ScrubbedBytes

-- | A public key and its corresponding secret key.
data KeyPair = KeyPair
  { publicKey :: !ByteString,
    secretKey :: !SecretBytes
  }
  deriving (Eq)

instance Show KeyPair where
  showsPrec _ keys =
    showString "KeyPair {publicKey = <"
      . shows (BS.length (publicKey keys))
      . showString " bytes>, secretKey = <redacted>}"

-- | A ciphertext and the shared secret established for its recipient.
data EncapsulatedSecret = EncapsulatedSecret
  { ciphertext :: !ByteString,
    sharedSecret :: !SecretBytes
  }
  deriving (Eq)

instance Show EncapsulatedSecret where
  showsPrec _ value =
    showString "EncapsulatedSecret {ciphertext = <"
      . shows (BS.length (ciphertext value))
      . showString " bytes>, sharedSecret = <redacted>}"

-- | Native operation associated with a failure.
data Operation
  = KeyGeneration
  | Signing
  | Verification
  | Encapsulation
  | Decapsulation
  deriving (Eq, Show)

-- | Errors reported before or during a native operation.
data KpqCError
  = InvalidSize !String !Int !Int
  | ContextTooLong !Int
  | NativeFailure !Operation !Int
  | UnexpectedOutputSize !Operation !Int !Int
  deriving (Eq, Show)

-- | Algorithms that can generate a key pair.
class Algorithm algorithm where
  algorithmId :: algorithm -> String
  generateKeyPair :: algorithm -> IO (Either KpqCError KeyPair)

instance Algorithm SignatureAlgorithm where
  algorithmId algorithm = case algorithm of
    AIMer128f -> "aimer-128f"
    AIMer128s -> "aimer-128s"
    AIMer192f -> "aimer-192f"
    AIMer192s -> "aimer-192s"
    AIMer256f -> "aimer-256f"
    AIMer256s -> "aimer-256s"
    HAETAE2 -> "haetae-mode2"
    HAETAE3 -> "haetae-mode3"
    HAETAE5 -> "haetae-mode5"

  generateKeyPair algorithm =
    let sizes = signatureSizes algorithm
        (keyPairFunction, _, _) = signatureBackend algorithm
     in runKeyPair
          (signaturePublicKeyBytes sizes)
          (signatureSecretKeyBytes sizes)
          keyPairFunction

instance Algorithm KEMAlgorithm where
  algorithmId algorithm = case algorithm of
    NTRUPlus768 -> "NTRU+768"
    NTRUPlus864 -> "NTRU+864"
    NTRUPlus1152 -> "NTRU+1152"
    SMAUGT128 -> "SMAUG-T128"
    SMAUGT192 -> "SMAUG-T192"
    SMAUGT256 -> "SMAUG-T256"
    TiMER -> "TiMER"

  generateKeyPair algorithm =
    let sizes = kemSizes algorithm
        (keyPairFunction, _, _) = kemBackend algorithm
     in runKeyPair
          (kemPublicKeyBytes sizes)
          (kemSecretKeyBytes sizes)
          keyPairFunction

-- | Every supported signature parameter set.
signatureAlgorithms :: [SignatureAlgorithm]
signatureAlgorithms = [minBound .. maxBound]

-- | Every supported key-encapsulation parameter set.
kemAlgorithms :: [KEMAlgorithm]
kemAlgorithms = [minBound .. maxBound]

-- | Return the fixed byte lengths for a signature parameter set.
signatureSizes :: SignatureAlgorithm -> SignatureSizes
signatureSizes algorithm = case algorithm of
  AIMer128f -> SignatureSizes 32 48 6944
  AIMer128s -> SignatureSizes 32 48 4704
  AIMer192f -> SignatureSizes 48 72 15408
  AIMer192s -> SignatureSizes 48 72 10320
  AIMer256f -> SignatureSizes 64 96 31360
  AIMer256s -> SignatureSizes 64 96 20224
  HAETAE2 -> SignatureSizes 992 1408 1474
  HAETAE3 -> SignatureSizes 1472 2112 2349
  HAETAE5 -> SignatureSizes 2080 2752 2948

-- | Return the fixed byte lengths for a key-encapsulation parameter set.
kemSizes :: KEMAlgorithm -> KEMSizes
kemSizes algorithm = case algorithm of
  NTRUPlus768 -> KEMSizes 1152 2336 1152 32
  NTRUPlus864 -> KEMSizes 1296 2624 1296 32
  NTRUPlus1152 -> KEMSizes 1728 3488 1728 32
  SMAUGT128 -> KEMSizes 672 832 672 32
  SMAUGT192 -> KEMSizes 1088 1312 992 32
  SMAUGT256 -> KEMSizes 1440 1728 1376 32
  TiMER -> KEMSizes 672 832 608 32

-- | Sign a message using an empty domain-separation context.
sign :: BA.ByteArrayAccess secret => SignatureAlgorithm -> ByteString -> secret -> IO (Either KpqCError ByteString)
sign algorithm message secret = signWithContext algorithm message secret BS.empty

-- | Sign a message with a domain-separation context of at most 255 bytes.
signWithContext :: BA.ByteArrayAccess secret => SignatureAlgorithm -> ByteString -> secret -> ByteString -> IO (Either KpqCError ByteString)
signWithContext algorithm message secret context =
  let sizes = signatureSizes algorithm
      expectedSecret = signatureSecretKeyBytes sizes
      expectedSignature = signatureBytes sizes
      (_, signFunction, _) = signatureBackend algorithm
   in case validateSize "secret key" expectedSecret secret of
        Left failure -> pure (Left failure)
        Right () -> case validateContext context of
          Left failure -> pure (Left failure)
          Right () ->
            runSizedOutput Signing expectedSignature $ \signaturePointer ->
              alloca $ \lengthPointer -> do
                poke lengthPointer 0
                status <-
                  withBytes message $ \messagePointer messageLength ->
                    withBytes context $ \contextPointer contextLength ->
                      withBytes secret $ \secretPointer _ ->
                        signFunction
                          signaturePointer
                          lengthPointer
                          messagePointer
                          messageLength
                          contextPointer
                          contextLength
                          secretPointer
                actualLength <- fromIntegral <$> peek lengthPointer
                pure (status, actualLength)

-- | Verify a signature using an empty domain-separation context.
verify :: SignatureAlgorithm -> ByteString -> ByteString -> ByteString -> IO (Either KpqCError Bool)
verify algorithm message signature public =
  verifyWithContext algorithm message signature public BS.empty

-- | Verify a signature with the domain-separation context used when signing.
verifyWithContext :: SignatureAlgorithm -> ByteString -> ByteString -> ByteString -> ByteString -> IO (Either KpqCError Bool)
verifyWithContext algorithm message signature public context =
  let sizes = signatureSizes algorithm
      expectedPublic = signaturePublicKeyBytes sizes
      expectedSignature = signatureBytes sizes
      (_, _, verifyFunction) = signatureBackend algorithm
   in case validateSize "public key" expectedPublic public of
        Left failure -> pure (Left failure)
        Right () -> case validateContext context of
          Left failure -> pure (Left failure)
          Right ()
            | BS.length signature /= expectedSignature -> pure (Right False)
            | otherwise -> do
                status <-
                  withBytes signature $ \signaturePointer signatureLength ->
                    withBytes message $ \messagePointer messageLength ->
                      withBytes context $ \contextPointer contextLength ->
                        withBytes public $ \publicPointer _ ->
                          verifyFunction
                            signaturePointer
                            signatureLength
                            messagePointer
                            messageLength
                            contextPointer
                            contextLength
                            publicPointer
                pure $ case status of
                  0 -> Right True
                  -1 -> Right False
                  _ -> Left (NativeFailure Verification (fromIntegral status))

-- | Encapsulate a new shared secret to a public key.
encapsulate :: KEMAlgorithm -> ByteString -> IO (Either KpqCError EncapsulatedSecret)
encapsulate algorithm public =
  let sizes = kemSizes algorithm
      expectedPublic = kemPublicKeyBytes sizes
      expectedCiphertext = ciphertextBytes sizes
      expectedSecret = sharedSecretBytes sizes
      (_, encapsulateFunction, _) = kemBackend algorithm
   in case validateSize "public key" expectedPublic public of
        Left failure -> pure (Left failure)
        Right () ->
          runTwoOutputs Encapsulation expectedCiphertext expectedSecret EncapsulatedSecret $ \ciphertextPointer sharedSecretPointer ->
            withBytes public $ \publicPointer _ ->
              encapsulateFunction ciphertextPointer sharedSecretPointer publicPointer

-- | Decapsulate a shared secret from a ciphertext.
decapsulate :: BA.ByteArrayAccess secret => KEMAlgorithm -> ByteString -> secret -> IO (Either KpqCError SecretBytes)
decapsulate algorithm encrypted secret =
  let sizes = kemSizes algorithm
      expectedCiphertext = ciphertextBytes sizes
      expectedSecretKey = kemSecretKeyBytes sizes
      expectedSharedSecret = sharedSecretBytes sizes
      (_, _, decapsulateFunction) = kemBackend algorithm
   in case validateSize "ciphertext" expectedCiphertext encrypted of
        Left failure -> pure (Left failure)
        Right () -> case validateSize "secret key" expectedSecretKey secret of
          Left failure -> pure (Left failure)
          Right () ->
            runSecretOutput Decapsulation expectedSharedSecret $ \sharedSecretPointer ->
              withBytes encrypted $ \ciphertextPointer _ ->
                withBytes secret $ \secretPointer _ ->
                  decapsulateFunction sharedSecretPointer ciphertextPointer secretPointer

type KeyPairFunction = Ptr Word8 -> Ptr Word8 -> IO CInt

type SignFunction = Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

type VerifyFunction = Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

type EncapsulateFunction = Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

type DecapsulateFunction = Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

signatureBackend :: SignatureAlgorithm -> (KeyPairFunction, SignFunction, VerifyFunction)
signatureBackend algorithm = case algorithm of
  AIMer128f -> (AIMer.aimer128fKeyPair, AIMer.aimer128fSign, AIMer.aimer128fVerify)
  AIMer128s -> (AIMer.aimer128sKeyPair, AIMer.aimer128sSign, AIMer.aimer128sVerify)
  AIMer192f -> (AIMer.aimer192fKeyPair, AIMer.aimer192fSign, AIMer.aimer192fVerify)
  AIMer192s -> (AIMer.aimer192sKeyPair, AIMer.aimer192sSign, AIMer.aimer192sVerify)
  AIMer256f -> (AIMer.aimer256fKeyPair, AIMer.aimer256fSign, AIMer.aimer256fVerify)
  AIMer256s -> (AIMer.aimer256sKeyPair, AIMer.aimer256sSign, AIMer.aimer256sVerify)
  HAETAE2 -> (HAETAE.haetae2KeyPair, HAETAE.haetae2Sign, HAETAE.haetae2Verify)
  HAETAE3 -> (HAETAE.haetae3KeyPair, HAETAE.haetae3Sign, HAETAE.haetae3Verify)
  HAETAE5 -> (HAETAE.haetae5KeyPair, HAETAE.haetae5Sign, HAETAE.haetae5Verify)

kemBackend :: KEMAlgorithm -> (KeyPairFunction, EncapsulateFunction, DecapsulateFunction)
kemBackend algorithm = case algorithm of
  NTRUPlus768 -> (NTRUPlus.ntruplus768KeyPair, NTRUPlus.ntruplus768Encapsulate, NTRUPlus.ntruplus768Decapsulate)
  NTRUPlus864 -> (NTRUPlus.ntruplus864KeyPair, NTRUPlus.ntruplus864Encapsulate, NTRUPlus.ntruplus864Decapsulate)
  NTRUPlus1152 -> (NTRUPlus.ntruplus1152KeyPair, NTRUPlus.ntruplus1152Encapsulate, NTRUPlus.ntruplus1152Decapsulate)
  SMAUGT128 -> (SMAUGT.smaugt128KeyPair, SMAUGT.smaugt128Encapsulate, SMAUGT.smaugt128Decapsulate)
  SMAUGT192 -> (SMAUGT.smaugt192KeyPair, SMAUGT.smaugt192Encapsulate, SMAUGT.smaugt192Decapsulate)
  SMAUGT256 -> (SMAUGT.smaugt256KeyPair, SMAUGT.smaugt256Encapsulate, SMAUGT.smaugt256Decapsulate)
  TiMER -> (SMAUGT.timerKeyPair, SMAUGT.timerEncapsulate, SMAUGT.timerDecapsulate)

runKeyPair :: Int -> Int -> KeyPairFunction -> IO (Either KpqCError KeyPair)
runKeyPair publicLength secretLength keyPairFunction =
  runTwoOutputs KeyGeneration publicLength secretLength KeyPair keyPairFunction

runSecretOutput :: Operation -> Int -> (Ptr Word8 -> IO CInt) -> IO (Either KpqCError SecretBytes)
runSecretOutput operation size action = do
  (status, secret) <-
    BA.allocRet size $ \pointer -> do
      fillBytes pointer 0 size
      result <- action (castPtr pointer)
      when (result /= 0) (fillBytes pointer 0 size)
      pure result
  if status == 0
    then pure (Right secret)
    else pure (Left (NativeFailure operation (fromIntegral status)))

runSizedOutput :: Operation -> Int -> (Ptr Word8 -> IO (CInt, Int)) -> IO (Either KpqCError ByteString)
runSizedOutput operation expected action =
  allocaArray expected $ \pointer ->
    ( do
        fillBytes pointer 0 expected
        (status, actual) <- action pointer
        if status /= 0
          then pure (Left (NativeFailure operation (fromIntegral status)))
          else
            if actual /= expected
              then pure (Left (UnexpectedOutputSize operation expected actual))
              else Right <$> BS.packCStringLen (castPtr pointer, expected)
    )
      `finally` fillBytes pointer 0 expected

runTwoOutputs :: Operation -> Int -> Int -> (ByteString -> SecretBytes -> value) -> (Ptr Word8 -> Ptr Word8 -> IO CInt) -> IO (Either KpqCError value)
runTwoOutputs operation firstSize secondSize constructor action =
  allocaArray firstSize $ \firstPointer ->
    ( do
        fillBytes firstPointer 0 firstSize
        (status, second) <-
          BA.allocRet secondSize $ \secondPointer -> do
            fillBytes secondPointer 0 secondSize
            result <- action firstPointer (castPtr secondPointer)
            when (result /= 0) (fillBytes secondPointer 0 secondSize)
            pure result
        if status == 0
          then do
            first <- BS.packCStringLen (castPtr firstPointer, firstSize)
            pure (Right (constructor first second))
          else pure (Left (NativeFailure operation (fromIntegral status)))
    )
      `finally` fillBytes firstPointer 0 firstSize

withBytes :: BA.ByteArrayAccess bytes => bytes -> (Ptr Word8 -> CSize -> IO value) -> IO value
withBytes bytes action =
  BA.withByteArray bytes $ \pointer ->
    action (castPtr pointer) (fromIntegral (BA.length bytes))

validateSize :: BA.ByteArrayAccess bytes => String -> Int -> bytes -> Either KpqCError ()
validateSize label expected value
  | actual == expected = Right ()
  | otherwise = Left (InvalidSize label expected actual)
  where
    actual = BA.length value

validateContext :: ByteString -> Either KpqCError ()
validateContext context
  | size <= 255 = Right ()
  | otherwise = Left (ContextTooLong size)
  where
    size = BS.length context
