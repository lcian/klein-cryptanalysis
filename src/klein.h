#include <stdint.h>


void init_cipher();

void sub_nibbles(uint8_t* x);
void inv_mix_nibbles(uint8_t* x);

void encrypt(uint8_t* x, uint8_t* y);

void encrypt_with_given_key(uint8_t* x, uint8_t* y, uint8_t* k);
