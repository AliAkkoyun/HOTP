//
//  main.c
//  RFC4226
//
//  Created by Ali AKKOYUN on 18.05.2024.
//

/*
    NOTLAR
    -> kodu çalıştırmak için gereken compiler kodu : gcc -o main main.c -I/usr/local/include/node -L//opt/homebrew/Cellar/openssl@3/3.3.0/lib -lssl -lcrypto
    -> Macos da yazıldığı için windows işletim sisteminde gerekli ayarlamalar yapılması gerekmektedir.
    -> OpenSSL 3.3.0 versionu kullanılmıştır ve sadece SHA256 projeye dahil edilmiştir.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <openssl/sha.h>


#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_LENGTH 32
#define OTP_DIGITS 6

uint32_t hotp(const uint8_t *key, size_t key_len, uint64_t counter);
void hash_sha256(const unsigned char* x,const size_t xlen,const unsigned char* y,const size_t ylen,unsigned char* out,size_t outlen);
void hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *message, size_t message_len, unsigned char *hmac);
void generate_random_key(uint8_t* key, size_t key_size);

int main() {

    uint64_t counter = 3;
    unsigned char secret_key[SHA256_DIGEST_LENGTH] = {
    0xa8, 0x41, 0x41, 0x9b, 0xcf, 0x3c, 0x5e, 0x31,
    0x8f, 0x63, 0x02, 0xd9, 0x02, 0x6f, 0x5d, 0x23,
    0x8e, 0xda, 0xb7, 0xb2, 0x11, 0xe6, 0xd5, 0x96,
    0x2d, 0x57, 0x01, 0x4c, 0x00, 0x6a, 0x26, 0x72
    };

    uint32_t otp = hotp(secret_key, SHA256_DIGEST_LENGTH, counter);
    printf("HOTP: %06u\n", otp);

    return 0;
}

uint32_t hotp(const uint8_t *key, size_t key_len, uint64_t counter) {
    unsigned char counter_bytes[8];
    unsigned char hmac[SHA256_DIGEST_LENGTH]; 

    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xff;
        counter >>= 8;
    }

    hmac_sha256(key, key_len, counter_bytes, sizeof(counter_bytes), hmac);

    int offset = hmac[31] & 0x0f;
    uint32_t binary = ((hmac[offset] & 0x7f) << 24) |
                      ((hmac[offset + 1] & 0xff) << 16) |
                      ((hmac[offset + 2] & 0xff) << 8) |
                      (hmac[offset + 3] & 0xff);

    uint32_t otp = binary % (uint32_t)(pow(10, OTP_DIGITS)); 
    return otp;
}

void hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *message, size_t message_len, unsigned char *hmac) {

    uint8_t adjusted_key[SHA256_BLOCK_SIZE];
    uint8_t inner_key_pad[SHA256_BLOCK_SIZE];
    uint8_t outer_key_pad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_LENGTH];
    uint8_t outer_hash[SHA256_DIGEST_LENGTH];

    if (key_len > SHA256_BLOCK_SIZE) {
        SHA256(key, key_len, adjusted_key);
        key_len = SHA256_DIGEST_LENGTH;
    } else {
        memcpy(adjusted_key, key, key_len);
    }


    // Anahtarın iç ve dış özetlerini hazırla
    for (uint32_t i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        inner_key_pad[i] = adjusted_key[i] ^ 0x36;
        outer_key_pad[i] = adjusted_key[i] ^ 0x5C;
    }

    

    hash_sha256(inner_key_pad, SHA256_DIGEST_LENGTH, message, message_len, inner_hash, sizeof(inner_hash));
    hash_sha256(outer_key_pad, SHA256_DIGEST_LENGTH, inner_hash, sizeof(inner_hash), outer_hash, sizeof(outer_hash));
    
    memcpy(hmac, outer_hash, SHA256_DIGEST_LENGTH);

}

void hash_sha256(const unsigned char* x,
               const size_t xlen,
               const unsigned char* y,
               const size_t ylen,
                unsigned char* out,
               const size_t outlen) {

  size_t buflen = (xlen + ylen);
  uint8_t* buf = (uint8_t*)malloc(buflen);

  memcpy(buf, x, xlen);
  memcpy(buf + xlen, y, ylen);

  SHA256(buf, buflen, out);

  free(buf);
}
