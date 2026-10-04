module Main (main) where

import Control.Monad (forM_, unless)
import Crypto.KpqC
import Data.Bits (xor)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.Exit (exitFailure)

main :: IO ()
main = do
  assertEqual "signature algorithm count" 9 (length signatureAlgorithms)
  assertEqual "KEM algorithm count" 7 (length kemAlgorithms)
  forM_ signatureAlgorithms checkSignature
  forM_ kemAlgorithms checkKEM
  checkValidation
  putStrLn "All KpqC tests passed."

checkSignature :: SignatureAlgorithm -> IO ()
checkSignature algorithm = do
  keys <- expectRight (generateKeyPair algorithm)
  let sizes = signatureSizes algorithm
      message = BSC.pack "KpqC Haskell"
      context = BSC.pack "release"
  assertEqual "signature public-key size" (signaturePublicKeyBytes sizes) (BS.length (publicKey keys))
  assertEqual "signature secret-key size" (signatureSecretKeyBytes sizes) (BA.length (secretKey keys))
  assertEqual
    "key-pair display redacts the secret key"
    ("KeyPair {publicKey = <" ++ show (signaturePublicKeyBytes sizes) ++ " bytes>, secretKey = <redacted>}")
    (show keys)
  signature <- expectRight (signWithContext algorithm message (secretKey keys) context)
  assertEqual "signature size" (signatureBytes sizes) (BS.length signature)
  expectRight (verifyWithContext algorithm message signature (publicKey keys) context) >>= assertTrue "valid signature"
  expectRight (verifyWithContext algorithm message (flipFirst signature) (publicKey keys) context) >>= assertFalse "modified signature"
  expectRight (verifyWithContext algorithm (BS.snoc message 33) signature (publicKey keys) context) >>= assertFalse "modified message"
  expectRight (verifyWithContext algorithm message signature (publicKey keys) (BSC.pack "wrong")) >>= assertFalse "wrong context"
  expectRight (verify algorithm message (BS.singleton 0) (publicKey keys)) >>= assertFalse "wrong signature length"

checkKEM :: KEMAlgorithm -> IO ()
checkKEM algorithm = do
  keys <- expectRight (generateKeyPair algorithm)
  let sizes = kemSizes algorithm
  assertEqual "KEM public-key size" (kemPublicKeyBytes sizes) (BS.length (publicKey keys))
  assertEqual "KEM secret-key size" (kemSecretKeyBytes sizes) (BA.length (secretKey keys))
  outbound <- expectRight (encapsulate algorithm (publicKey keys))
  assertEqual "ciphertext size" (ciphertextBytes sizes) (BS.length (ciphertext outbound))
  assertEqual "shared-secret size" (sharedSecretBytes sizes) (BA.length (sharedSecret outbound))
  assertEqual
    "encapsulation display redacts the shared secret"
    ("EncapsulatedSecret {ciphertext = <" ++ show (ciphertextBytes sizes) ++ " bytes>, sharedSecret = <redacted>}")
    (show outbound)
  inbound <- expectRight (decapsulate algorithm (ciphertext outbound) (secretKey keys))
  assertEqual "shared secrets" (sharedSecret outbound) inbound
  rejection <- decapsulate algorithm (flipFirst (ciphertext outbound)) (secretKey keys)
  case algorithm of
    NTRUPlus768 -> assertNativeFailure rejection
    NTRUPlus864 -> assertNativeFailure rejection
    NTRUPlus1152 -> assertNativeFailure rejection
    _ -> do
      replacement <- expectEitherRight rejection
      assertEqual "replacement-secret size" (sharedSecretBytes sizes) (BA.length replacement)
      assertTrue "implicit rejection" (replacement /= sharedSecret outbound)

checkValidation :: IO ()
checkValidation = do
  keys <- expectRight (generateKeyPair AIMer128f)
  invalidSecret <- sign AIMer128f BS.empty (BS.singleton 0)
  assertEqual "invalid secret key" (Left (InvalidSize "secret key" 48 1)) invalidSecret
  longContext <- signWithContext AIMer128f BS.empty (secretKey keys) (BS.replicate 256 0)
  assertEqual "long context" (Left (ContextTooLong 256)) longContext
  invalidPublic <- verify AIMer128f BS.empty BS.empty (BS.singleton 0)
  assertEqual "invalid public key" (Left (InvalidSize "public key" 32 1)) invalidPublic
  invalidCiphertext <- decapsulate NTRUPlus768 (BS.singleton 0) (BS.replicate 2336 0)
  assertEqual "invalid ciphertext" (Left (InvalidSize "ciphertext" 1152 1)) invalidCiphertext

flipFirst :: ByteString -> ByteString
flipFirst input = case BS.uncons input of
  Nothing -> input
  Just (first, rest) -> BS.cons (first `xor` 1) rest

assertNativeFailure :: Either KpqCError SecretBytes -> IO ()
assertNativeFailure result = case result of
  Left (NativeFailure Decapsulation _) -> pure ()
  _ -> failTest ("expected native decapsulation failure, received " ++ show result)

expectRight :: IO (Either KpqCError value) -> IO value
expectRight operation = operation >>= expectEitherRight

expectEitherRight :: Either KpqCError value -> IO value
expectEitherRight result = case result of
  Right value -> pure value
  Left failure -> failTest ("unexpected failure: " ++ show failure)

assertTrue :: String -> Bool -> IO ()
assertTrue label value = unless value (failTest (label ++ ": expected True"))

assertFalse :: String -> Bool -> IO ()
assertFalse label = assertTrue label . not

assertEqual :: (Eq value, Show value) => String -> value -> value -> IO ()
assertEqual label expected actual =
  unless (expected == actual) $
    failTest (label ++ ": expected " ++ show expected ++ ", received " ++ show actual)

failTest :: String -> IO value
failTest message = do
  putStrLn ("FAIL: " ++ message)
  exitFailure
