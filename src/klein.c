#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "common.h"
#include "speedklein64.h"
#include "kleinSbox.h"
#include "config.h"


uint8_t K[8];
uint8_t EK[NR][8];
// Initialize K and EK (master and round keys)
void init_cipher(){
    if(random_key){
        for(int i=0; i<8; i++)
            K[i] = (uint8_t) (rand() % 256);
    } else {
        memcpy(K, Key, sizeof(uint8_t) * 8);
    }
    if(print_key){
        printf("\nKey:\n");
        print_matrix(K);
    }
    klein64_expandKey(K, NR, EK);
}

void sub_nibbles(uint8_t* x){
	for(int i=0; i<8; i++)
		x[i] = sbox8[x[i]];
}

// Taken from speedKlein64.h
void inv_mix_nibbles(uint8_t* state){
	uint8_t u = 0;
	uint8_t v = 0;
	uint8_t temp_state[8];

    temp_state[0] = state[0];
    temp_state[1] = state[1];
    temp_state[2] = state[2];
    temp_state[3] = state[3];
    temp_state[4] = state[4];
    temp_state[5] = state[5];
    temp_state[6] = state[6];
    temp_state[7] = state[7];

    u = multiply2[multiply2[temp_state[0] ^ temp_state[2]]];
    v = multiply2[multiply2[temp_state[1] ^ temp_state[3]]];

    temp_state[0] = temp_state[0] ^ u;
    temp_state[1] = temp_state[1] ^ v;
    temp_state[2] = temp_state[2] ^ u;
    temp_state[3] = temp_state[3] ^ v;

    u = multiply2[multiply2[temp_state[4] ^ temp_state[6]]];
    v = multiply2[multiply2[temp_state[5] ^ temp_state[7]]];

    temp_state[4] = temp_state[4] ^ u;
    temp_state[5] = temp_state[5] ^ v;
    temp_state[6] = temp_state[6] ^ u;
    temp_state[7] = temp_state[7] ^ v;

    u = temp_state[0] ^ temp_state[1] ^ temp_state[2] ^ temp_state[3];
    v = temp_state[0] ^ temp_state[1];
    v = multiply2[v];
    state[0] = temp_state[0] ^ v ^ u;

    v = temp_state[1] ^ temp_state[2];
    v = multiply2[v];
    state[1] = temp_state[1] ^ v ^ u;

    v = temp_state[2] ^ temp_state[3];
    v = multiply2[v];
    state[2] = temp_state[2] ^ v ^ u;

    v = temp_state[3] ^ temp_state[0];
    v = multiply2[v];
    state[3] = temp_state[3] ^ v ^ u;

    u = temp_state[4] ^ temp_state[5] ^ temp_state[6] ^ temp_state[7];
    v = temp_state[4] ^ temp_state[5];
    v = multiply2[v];
    state[4] = temp_state[4] ^ v ^ u;

    v = temp_state[5] ^ temp_state[6];
    v = multiply2[v];
    state[5] = temp_state[5] ^ v ^ u;

    v = temp_state[6] ^ temp_state[7];
    v = multiply2[v];
    state[6] = temp_state[6] ^ v ^ u;

    v = temp_state[7] ^ temp_state[4];
    v = multiply2[v];
    state[7] = temp_state[7] ^ v ^ u;
}

// Encryption oracle
void encrypt(uint8_t* x, uint8_t* y){
    klein64_encrypt_rounds(x, EK, NR, y);
}

// Encrypt with user supplied key
void encrypt_with_given_key(uint8_t* x, uint8_t* y, uint8_t* k){
    uint8_t ekey[NR][8];
    klein64_expandKey(k, NR, ekey);
    klein64_encrypt_rounds(x, ekey, NR, y);
}
