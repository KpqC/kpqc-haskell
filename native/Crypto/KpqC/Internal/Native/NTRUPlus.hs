{-# LANGUAGE CPP #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.KpqC.Internal.Native.NTRUPlus where

import Data.Word (Word8)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)

#ifdef KPQC_TEST_ENTROPY
import Foreign.C.Types (CSize (..))
#endif

foreign import ccall safe "kpqc_ntruplus768_keypair" ntruplus768KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_ntruplus768_encapsulate" ntruplus768Encapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_ntruplus768_decapsulate" ntruplus768Decapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_ntruplus864_keypair" ntruplus864KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_ntruplus864_encapsulate" ntruplus864Encapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_ntruplus864_decapsulate" ntruplus864Decapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall safe "kpqc_ntruplus1152_keypair" ntruplus1152KeyPair :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_ntruplus1152_encapsulate" ntruplus1152Encapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall safe "kpqc_ntruplus1152_decapsulate" ntruplus1152Decapsulate :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

#ifdef KPQC_TEST_ENTROPY
foreign import ccall safe "kpqc_ntruplus768_set_test_entropy" ntruplus768SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_ntruplus768_test_entropy_remaining" ntruplus768TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_ntruplus768_clear_test_entropy" ntruplus768ClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_ntruplus864_set_test_entropy" ntruplus864SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_ntruplus864_test_entropy_remaining" ntruplus864TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_ntruplus864_clear_test_entropy" ntruplus864ClearTestEntropy :: IO ()
foreign import ccall safe "kpqc_ntruplus1152_set_test_entropy" ntruplus1152SetTestEntropy :: Ptr Word8 -> CSize -> IO CInt
foreign import ccall safe "kpqc_ntruplus1152_test_entropy_remaining" ntruplus1152TestEntropyRemaining :: IO CSize
foreign import ccall safe "kpqc_ntruplus1152_clear_test_entropy" ntruplus1152ClearTestEntropy :: IO ()
#endif
