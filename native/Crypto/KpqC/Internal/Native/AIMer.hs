{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.KpqC.Internal.Native.AIMer where

import Data.Word (Word8, Word64)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr)

foreign import ccall safe "kpqc_aimer128f_keypair" aimer128fKeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer128f_sign" aimer128fSign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer128f_verify" aimer128fVerify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_aimer128s_keypair" aimer128sKeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer128s_sign" aimer128sSign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer128s_verify" aimer128sVerify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_aimer192f_keypair" aimer192fKeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer192f_sign" aimer192fSign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer192f_verify" aimer192fVerify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_aimer192s_keypair" aimer192sKeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer192s_sign" aimer192sSign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer192s_verify" aimer192sVerify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_aimer256f_keypair" aimer256fKeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer256f_sign" aimer256fSign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer256f_verify" aimer256fVerify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_aimer256s_keypair" aimer256sKeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer256s_sign" aimer256sSign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_aimer256s_verify" aimer256sVerify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

#ifdef KPQC_TEST_ENTROPY
foreign import ccall safe "kpqc_aimer128f_set_test_entropy" aimer128fSetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_aimer128f_test_entropy_remaining" aimer128fTestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_aimer128f_clear_test_entropy" aimer128fClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_aimer128s_set_test_entropy" aimer128sSetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_aimer128s_test_entropy_remaining" aimer128sTestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_aimer128s_clear_test_entropy" aimer128sClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_aimer192f_set_test_entropy" aimer192fSetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_aimer192f_test_entropy_remaining" aimer192fTestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_aimer192f_clear_test_entropy" aimer192fClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_aimer192s_set_test_entropy" aimer192sSetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_aimer192s_test_entropy_remaining" aimer192sTestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_aimer192s_clear_test_entropy" aimer192sClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_aimer256f_set_test_entropy" aimer256fSetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_aimer256f_test_entropy_remaining" aimer256fTestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_aimer256f_clear_test_entropy" aimer256fClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_aimer256s_set_test_entropy" aimer256sSetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_aimer256s_test_entropy_remaining" aimer256sTestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_aimer256s_clear_test_entropy" aimer256sClearTestEntropy :: IO ()
#endif
