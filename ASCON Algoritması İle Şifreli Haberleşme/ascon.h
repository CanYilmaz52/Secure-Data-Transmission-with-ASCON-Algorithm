#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stddef.h>

// Ascon algoritması için gerekli şifreleme ve şifre çözme fonksiyonları
void ascon_encrypt(uint8_t *ciphertext, const uint8_t *plaintext, size_t len, const uint8_t *key, const uint8_t *nonce);
int ascon_decrypt(uint8_t *decrypted_text, const uint8_t *ciphertext, size_t len, const uint8_t *key, const uint8_t *nonce);

#endif /* ASCON_H */