{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.KpqC.Internal.Native.SMAUGT where

import Data.Word (Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)

#ifdef KPQC_TEST_ENTROPY
import Foreign.C.Types (CSize (..))
#endif

foreign import ccall safe "kpqc_smaugt128_keypair" smaugt128KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_smaugt128_encapsulate" smaugt128Encapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_smaugt128_decapsulate" smaugt128Decapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_smaugt192_keypair" smaugt192KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_smaugt192_encapsulate" smaugt192Encapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_smaugt192_decapsulate" smaugt192Decapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_smaugt256_keypair" smaugt256KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_smaugt256_encapsulate" smaugt256Encapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_smaugt256_decapsulate" smaugt256Decapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_timer_keypair" timerKeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_timer_encapsulate" timerEncapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_timer_decapsulate" timerDecapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

#ifdef KPQC_TEST_ENTROPY
foreign import ccall safe "kpqc_smaugt128_set_test_entropy" smaugt128SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_smaugt128_test_entropy_remaining" smaugt128TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_smaugt128_clear_test_entropy" smaugt128ClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_smaugt192_set_test_entropy" smaugt192SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_smaugt192_test_entropy_remaining" smaugt192TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_smaugt192_clear_test_entropy" smaugt192ClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_smaugt256_set_test_entropy" smaugt256SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_smaugt256_test_entropy_remaining" smaugt256TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_smaugt256_clear_test_entropy" smaugt256ClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_timer_set_test_entropy" timerSetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_timer_test_entropy_remaining" timerTestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_timer_clear_test_entropy" timerClearTestEntropy :: IO ()
#endif
