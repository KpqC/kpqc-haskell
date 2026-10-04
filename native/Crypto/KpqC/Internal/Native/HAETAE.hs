{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.KpqC.Internal.Native.HAETAE where

import Data.Word (Word8, Word64)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr)

foreign import ccall safe "kpqc_haetae2_keypair" haetae2KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_haetae2_sign" haetae2Sign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_haetae2_verify" haetae2Verify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_haetae3_keypair" haetae3KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_haetae3_sign" haetae3Sign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_haetae3_verify" haetae3Verify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_haetae5_keypair" haetae5KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_haetae5_sign" haetae5Sign :: Ptr Word8 -> Ptr Word64 -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_haetae5_verify" haetae5Verify :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

#ifdef KPQC_TEST_ENTROPY
foreign import ccall safe "kpqc_haetae2_set_test_entropy" haetae2SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_haetae2_test_entropy_remaining" haetae2TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_haetae2_clear_test_entropy" haetae2ClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_haetae3_set_test_entropy" haetae3SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_haetae3_test_entropy_remaining" haetae3TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_haetae3_clear_test_entropy" haetae3ClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_haetae5_set_test_entropy" haetae5SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_haetae5_test_entropy_remaining" haetae5TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_haetae5_clear_test_entropy" haetae5ClearTestEntropy :: IO ()
#endif
