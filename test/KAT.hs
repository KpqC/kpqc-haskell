{-# LANGUAGE ForeignFunctionInterface #-}

module Main (main) where

import Control.Exception (finally)
import Control.Monad (forM_)
import Crypto.KpqC
import qualified Crypto.KpqC.Internal.Native.AIMer as AIMer
import qualified Crypto.KpqC.Internal.Native.HAETAE as HAETAE
import qualified Crypto.KpqC.Internal.Native.NTRUPlus as NTRUPlus
import qualified Crypto.KpqC.Internal.Native.SMAUGT as SMAUGT
import Data.Bits (shiftR, xor, (.&.))
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.Char (digitToInt, isHexDigit, isSpace)
import qualified Data.Map.Strict as Map
import Data.Word (Word8)
import Foreign.C.Types (CInt, CSize)
import Foreign.Marshal.Array (allocaArray)
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr (Ptr, castPtr)
import System.Environment (lookupEnv)
import System.Exit (exitFailure)
import System.FilePath ((</>))
import System.IO.Unsafe (unsafePerformIO)

foreign import ccall unsafe "kpqc_test_aes256_ecb" aes256EcbNative :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

data EntropyBackend = EntropyBackend
  { setEntropyNative :: Ptr Word8 -> CSize -> IO CInt,
    entropyRemainingNative :: IO CSize,
    clearEntropyNative :: IO ()
  }

data DRBG = DRBG
  { drbgKey :: !ByteString,
    drbgCounter :: !ByteString
  }

type Vector = Map.Map String String

main :: IO ()
main = do
  root <- maybe "../kpqc-test-vectors" id <$> lookupEnv "KPQC_TEST_VECTORS"
  signatureCount <- sum <$> mapM (checkSignatureVectors root) signatureConfigurations
  kemCount <- sum <$> mapM (checkKEMVectors root) kemConfigurations
  assertEqual "known-answer vector count" 1600 (signatureCount + kemCount)
  checkEntropyExhaustion
  putStrLn "All 1,600 KpqC known-answer vectors passed."

signatureConfigurations :: [(SignatureAlgorithm, FilePath, Bool, Int)]
signatureConfigurations =
  [ (AIMer128f, "aimer" </> "128f", False, 16),
    (AIMer128s, "aimer" </> "128s", False, 16),
    (AIMer192f, "aimer" </> "192f", False, 24),
    (AIMer192s, "aimer" </> "192s", False, 24),
    (AIMer256f, "aimer" </> "256f", False, 32),
    (AIMer256s, "aimer" </> "256s", False, 32),
    (HAETAE2, "haetae" </> "mode2", True, 32),
    (HAETAE3, "haetae" </> "mode3", True, 32),
    (HAETAE5, "haetae" </> "mode5", True, 32)
  ]

kemConfigurations :: [(KEMAlgorithm, FilePath, Int, Int)]
kemConfigurations =
  [ (NTRUPlus768, "ntruplus" </> "768", 0, 96),
    (NTRUPlus864, "ntruplus" </> "864", 0, 108),
    (NTRUPlus1152, "ntruplus" </> "1152", 0, 144),
    (SMAUGT128, "smaugt" </> "mode1", 2, 32),
    (SMAUGT192, "smaugt" </> "mode3", 2, 32),
    (SMAUGT256, "smaugt" </> "mode5", 2, 32),
    (TiMER, "smaugt" </> "modet", 2, 16)
  ]

checkSignatureVectors :: FilePath -> (SignatureAlgorithm, FilePath, Bool, Int) -> IO Int
checkSignatureVectors root (algorithm, relativePath, isHAETAE, seedBytes) = do
  vectors <- readVectors (root </> relativePath </> "kat.rsp")
  assertEqual (algorithmId algorithm ++ " vector count") 100 (length vectors)
  forM_ vectors $ \vector -> do
    let initial = newDRBG (field vector "seed")
    (keys, afterKeyPair) <-
      if isHAETAE
        then do
          let (entropy, next) = generate seedBytes initial
          result <- withExactEntropy (signatureEntropy algorithm) entropy (generateKeyPair algorithm)
          value <- expectRight result
          pure (value, next)
        else do
          (result, next) <- withRepeatedEntropy (signatureEntropy algorithm) seedBytes initial (generateKeyPair algorithm)
          value <- expectRight result
          pure (value, next)
    assertEqual (label vector "public key") (field vector "pk") (publicKey keys)
    assertEqual (label vector "secret key") (field vector "sk") (secretByteString (secretKey keys))
    let message = field vector "msg"
        expectedSignature =
          case Map.lookup "sig" vector of
            Just encoded -> decodeHex encoded
            Nothing -> BS.drop (BS.length message) (field vector "sm")
        (signingEntropy, afterSigningEntropy) = generate seedBytes afterKeyPair
        (context, _) =
          if isHAETAE
            then
              let (lengthByte, afterLength) = generate 1 afterSigningEntropy
                  contextLength = fromIntegral (BS.head lengthByte)
               in generate contextLength afterLength
            else (BS.empty, afterSigningEntropy)
    signature <-
      withExactEntropy
        (signatureEntropy algorithm)
        signingEntropy
        (signWithContext algorithm message (secretKey keys) context)
        >>= expectRight
    assertEqual (label vector "signature") expectedSignature signature
    verifyWithContext algorithm message expectedSignature (publicKey keys) context
      >>= expectRight
      >>= assertTrue (label vector "verification")
  pure (length vectors)

checkKEMVectors :: FilePath -> (KEMAlgorithm, FilePath, Int, Int) -> IO Int
checkKEMVectors root (algorithm, relativePath, keyCalls, encapsulationBytes) = do
  vectors <- readVectors (root </> relativePath </> "kat.rsp")
  assertEqual (algorithmId algorithm ++ " vector count") 100 (length vectors)
  forM_ vectors $ \vector -> do
    let initial = newDRBG (field vector "seed")
    (keys, afterKeyPair) <-
      if keyCalls == 0
        then do
          (result, next) <- withRepeatedEntropy (kemEntropy algorithm) 32 initial (generateKeyPair algorithm)
          value <- expectRight result
          pure (value, next)
        else do
          let (chunks, next) = generateMany keyCalls 32 initial
          result <- withExactEntropy (kemEntropy algorithm) (BS.concat chunks) (generateKeyPair algorithm)
          value <- expectRight result
          pure (value, next)
    assertEqual (label vector "public key") (field vector "pk") (publicKey keys)
    assertEqual (label vector "secret key") (field vector "sk") (secretByteString (secretKey keys))
    let (entropy, _) = generate encapsulationBytes afterKeyPair
    outbound <-
      withExactEntropy
        (kemEntropy algorithm)
        entropy
        (encapsulate algorithm (publicKey keys))
        >>= expectRight
    assertEqual (label vector "ciphertext") (field vector "ct") (ciphertext outbound)
    assertEqual (label vector "shared secret") (field vector "ss") (secretByteString (sharedSecret outbound))
    decapsulate algorithm (ciphertext outbound) (secretKey keys)
      >>= expectRight
      >>= assertEqual (label vector "decapsulation") (BA.convert (field vector "ss") :: SecretBytes)
  pure (length vectors)

checkEntropyExhaustion :: IO ()
checkEntropyExhaustion = do
  forM_ signatureAlgorithms $ \algorithm ->
    expectEntropyExhaustion (algorithmId algorithm) (signatureEntropy algorithm) (generateKeyPair algorithm)
  forM_ kemAlgorithms $ \algorithm ->
    expectEntropyExhaustion (algorithmId algorithm) (kemEntropy algorithm) (generateKeyPair algorithm)

expectEntropyExhaustion :: String -> EntropyBackend -> IO (Either KpqCError value) -> IO ()
expectEntropyExhaustion name backend operation = do
  setEntropy backend BS.empty
  result <- operation `finally` clearEntropyNative backend
  case result of
    Left (NativeFailure KeyGeneration _) -> pure ()
    Left failure -> failTest (name ++ " entropy exhaustion returned " ++ show failure)
    Right _ -> failTest (name ++ " accepted an exhausted entropy source")

secretByteString :: SecretBytes -> ByteString
secretByteString = BA.convert

withExactEntropy :: EntropyBackend -> ByteString -> IO value -> IO value
withExactEntropy backend entropy operation = do
  setEntropy backend entropy
  ( do
      result <- operation
      remaining <- (fromIntegral <$> entropyRemainingNative backend) :: IO Int
      assertEqual "unused deterministic entropy" 0 remaining
      pure result
    )
    `finally` clearEntropyNative backend

withRepeatedEntropy :: EntropyBackend -> Int -> DRBG -> IO value -> IO (value, DRBG)
withRepeatedEntropy backend callBytes state operation = do
  let (chunks, _) = generateMany 128 callBytes state
      entropy = BS.concat chunks
  setEntropy backend entropy
  ( do
      result <- operation
      remaining <- fromIntegral <$> entropyRemainingNative backend
      let consumed = BS.length entropy - remaining
      assertTrue "deterministic entropy was consumed" (consumed > 0)
      assertEqual "deterministic entropy chunk alignment" 0 (consumed `mod` callBytes)
      let (_, next) = generateMany (consumed `div` callBytes) callBytes state
      pure (result, next)
    )
    `finally` clearEntropyNative backend

setEntropy :: EntropyBackend -> ByteString -> IO ()
setEntropy backend entropy = do
  status <-
    BSU.unsafeUseAsCStringLen entropy $ \(pointer, size) ->
      setEntropyNative backend (castPtr pointer) (fromIntegral size)
  assertEqual "set deterministic entropy" 0 status

signatureEntropy :: SignatureAlgorithm -> EntropyBackend
signatureEntropy algorithm = case algorithm of
  AIMer128f -> EntropyBackend AIMer.aimer128fSetTestEntropy AIMer.aimer128fTestEntropyRemaining AIMer.aimer128fClearTestEntropy
  AIMer128s -> EntropyBackend AIMer.aimer128sSetTestEntropy AIMer.aimer128sTestEntropyRemaining AIMer.aimer128sClearTestEntropy
  AIMer192f -> EntropyBackend AIMer.aimer192fSetTestEntropy AIMer.aimer192fTestEntropyRemaining AIMer.aimer192fClearTestEntropy
  AIMer192s -> EntropyBackend AIMer.aimer192sSetTestEntropy AIMer.aimer192sTestEntropyRemaining AIMer.aimer192sClearTestEntropy
  AIMer256f -> EntropyBackend AIMer.aimer256fSetTestEntropy AIMer.aimer256fTestEntropyRemaining AIMer.aimer256fClearTestEntropy
  AIMer256s -> EntropyBackend AIMer.aimer256sSetTestEntropy AIMer.aimer256sTestEntropyRemaining AIMer.aimer256sClearTestEntropy
  HAETAE2 -> EntropyBackend HAETAE.haetae2SetTestEntropy HAETAE.haetae2TestEntropyRemaining HAETAE.haetae2ClearTestEntropy
  HAETAE3 -> EntropyBackend HAETAE.haetae3SetTestEntropy HAETAE.haetae3TestEntropyRemaining HAETAE.haetae3ClearTestEntropy
  HAETAE5 -> EntropyBackend HAETAE.haetae5SetTestEntropy HAETAE.haetae5TestEntropyRemaining HAETAE.haetae5ClearTestEntropy

kemEntropy :: KEMAlgorithm -> EntropyBackend
kemEntropy algorithm = case algorithm of
  NTRUPlus768 -> EntropyBackend NTRUPlus.ntruplus768SetTestEntropy NTRUPlus.ntruplus768TestEntropyRemaining NTRUPlus.ntruplus768ClearTestEntropy
  NTRUPlus864 -> EntropyBackend NTRUPlus.ntruplus864SetTestEntropy NTRUPlus.ntruplus864TestEntropyRemaining NTRUPlus.ntruplus864ClearTestEntropy
  NTRUPlus1152 -> EntropyBackend NTRUPlus.ntruplus1152SetTestEntropy NTRUPlus.ntruplus1152TestEntropyRemaining NTRUPlus.ntruplus1152ClearTestEntropy
  SMAUGT128 -> EntropyBackend SMAUGT.smaugt128SetTestEntropy SMAUGT.smaugt128TestEntropyRemaining SMAUGT.smaugt128ClearTestEntropy
  SMAUGT192 -> EntropyBackend SMAUGT.smaugt192SetTestEntropy SMAUGT.smaugt192TestEntropyRemaining SMAUGT.smaugt192ClearTestEntropy
  SMAUGT256 -> EntropyBackend SMAUGT.smaugt256SetTestEntropy SMAUGT.smaugt256TestEntropyRemaining SMAUGT.smaugt256ClearTestEntropy
  TiMER -> EntropyBackend SMAUGT.timerSetTestEntropy SMAUGT.timerTestEntropyRemaining SMAUGT.timerClearTestEntropy

newDRBG :: ByteString -> DRBG
newDRBG entropy
  | BS.length entropy == 48 = updateDRBG (DRBG (BS.replicate 32 0) (BS.replicate 16 0)) entropy
  | otherwise = error "CTR-DRBG seed must be 48 bytes"

generate :: Int -> DRBG -> (ByteString, DRBG)
generate size state =
  let blocks = (size + 15) `div` 16
      (output, advanced) = generateBlocks blocks state
   in (BS.take size (BS.concat output), updateDRBG advanced BS.empty)

generateMany :: Int -> Int -> DRBG -> ([ByteString], DRBG)
generateMany count size = run count []
  where
    run 0 chunks state = (reverse chunks, state)
    run remaining chunks state =
      let (chunk, next) = generate size state
       in run (remaining - 1) (chunk : chunks) next

updateDRBG :: DRBG -> ByteString -> DRBG
updateDRBG state provided =
  let (blocks, _) = generateBlocks 3 state
      material = xorBytes (BS.concat blocks) (provided <> BS.replicate (48 - BS.length provided) 0)
   in DRBG (BS.take 32 material) (BS.drop 32 material)

generateBlocks :: Int -> DRBG -> ([ByteString], DRBG)
generateBlocks count = run count []
  where
    run 0 blocks state = (reverse blocks, state)
    run remaining blocks state =
      let counter = incrementCounter (drbgCounter state)
          block = aes256 (drbgKey state) counter
          next = state {drbgCounter = counter}
       in run (remaining - 1) (block : blocks) next

aes256 :: ByteString -> ByteString -> ByteString
aes256 key block = unsafePerformIO $
  allocaArray 16 $ \output ->
    ( do
        fillBytes output 0 16
        BSU.unsafeUseAsCStringLen key $ \(keyPointer, _) ->
          BSU.unsafeUseAsCStringLen block $ \(blockPointer, _) ->
            aes256EcbNative output (castPtr keyPointer) (castPtr blockPointer)
        BS.packCStringLen (castPtr output, 16)
    )
      `finally` fillBytes output 0 16
{-# NOINLINE aes256 #-}

incrementCounter :: ByteString -> ByteString
incrementCounter counter = integerBytes 16 ((bytesInteger counter + 1) `mod` (2 ^ (128 :: Int)))

bytesInteger :: ByteString -> Integer
bytesInteger = BS.foldl' (\value byte -> value * 256 + fromIntegral byte) 0

integerBytes :: Int -> Integer -> ByteString
integerBytes size value =
  BS.pack [fromIntegral ((value `shiftR` (position * 8)) .&. 255) | position <- reverse [0 .. size - 1]]

xorBytes :: ByteString -> ByteString -> ByteString
xorBytes left right = BS.pack (BS.zipWith xor left right)

readVectors :: FilePath -> IO [Vector]
readVectors path = do
  contents <- readFile path
  pure (finish (foldl parseLine ([], Map.empty) (lines contents)))
  where
    finish (vectors, current)
      | Map.null current = reverse vectors
      | otherwise = reverse (current : vectors)
    parseLine (vectors, current) line =
      case splitField line of
        Just ("count", value)
          | not (Map.null current) -> (current : vectors, Map.singleton "count" value)
        Just (name, value) -> (vectors, Map.insert name value current)
        Nothing -> (vectors, current)

splitField :: String -> Maybe (String, String)
splitField line = case break (== '=') line of
  (name, '=' : value) -> Just (trim name, trim value)
  _ -> Nothing

trim :: String -> String
trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace

field :: Vector -> String -> ByteString
field vector name = maybe (error ("missing vector field: " ++ name)) decodeHex (Map.lookup name vector)

decodeHex :: String -> ByteString
decodeHex value
  | odd (length value) || any (not . isHexDigit) value = error "invalid hexadecimal vector field"
  | otherwise = BS.pack (decode value)
  where
    decode [] = []
    decode (high : low : rest) = fromIntegral (digitToInt high * 16 + digitToInt low) : decode rest
    decode _ = error "unreachable"

label :: Vector -> String -> String
label vector fieldName = Map.findWithDefault "?" "count" vector ++ " " ++ fieldName

expectRight :: Either KpqCError value -> IO value
expectRight result = case result of
  Right value -> pure value
  Left failure -> failTest ("unexpected failure: " ++ show failure)

assertTrue :: String -> Bool -> IO ()
assertTrue message condition = if condition then pure () else failTest message

assertEqual :: (Eq value, Show value) => String -> value -> value -> IO ()
assertEqual message expected actual =
  if expected == actual
    then pure ()
    else failTest (message ++ ": expected " ++ show expected ++ ", received " ++ show actual)

failTest :: String -> IO value
failTest message = do
  putStrLn ("FAIL: " ++ message)
  exitFailure
