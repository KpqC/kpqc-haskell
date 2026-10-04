#include <stdint.h>

#include "aes.h"

void kpqc_test_aes256_ecb(uint8_t *output, const uint8_t *key,
                          const uint8_t *input) {
    aes256ctx context;
    aes256_ecb_keyexp(&context, key);
    aes256_ecb(output, input, 1, &context);
    aes256_ctx_release(&context);
}
