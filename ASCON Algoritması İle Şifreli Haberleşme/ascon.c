#include "ascon.h"

// Ascon şifreleme fonksiyonu (Basitleştirilmiş XOR tabanlı şifreleme)
void ascon_encrypt(uint8_t *ciphertext, const uint8_t *plaintext, size_t len, const uint8_t *key, const uint8_t *nonce) {
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % 16];  // Basit XOR şifreleme
    }
}

// Ascon şifre çözme fonksiyonu (XOR tabanlı şifre çözme)
int ascon_decrypt(uint8_t *decrypted_text, const uint8_t *ciphertext, size_t len, const uint8_t *key, const uint8_t *nonce) {
    for (size_t i = 0; i < len; i++) {
        decrypted_text[i] = ciphertext[i] ^ key[i % 16];  // Basit XOR şifre çözme
    }
    return 0;  // Şifre çözme başarılı
}