#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "common.h"
#include "klein.h"
#include "config.h"


// Generate a random plaintext and store it in x
void gen_plaintext(uint8_t* x){
	for(int i=0; i<8; i++)
	  x[i] = (uint8_t) (rand() % 256);
}

// Generate a random plaintext pair with difference pattern of Figure d (1 or 2)
void gen_pair_with_difference(uint8_t* x1, uint8_t* x2, int d){
	gen_plaintext(x1);
	memcpy(x2, x1, sizeof(uint8_t) * 8);
	if(d == 1){
	 	x2[0] ^= (uint8_t) (rand() % 16);
		x2[1] ^= (uint8_t) (rand() % 16);
		x2[6] ^= (uint8_t) (rand() % 16);
		x2[7] ^= (uint8_t) (rand() % 16);
	} else {
	 	x2[2] ^= (uint8_t) (rand() % 16);
		x2[3] ^= (uint8_t) (rand() % 16);
		x2[4] ^= (uint8_t) (rand() % 16);
		x2[5] ^= (uint8_t) (rand() % 16);
	}	
}

// Encrypt x1 and x2 using the oracle and store the results in y1 and y2
// then return true iff x1, x2 is a good pair, i.e. the output difference
// obtained after inverting MixColumns on the ciphertexts
// has only lower nibbles possibly active
bool is_good_pair(uint8_t* x1, uint8_t* x2, uint8_t* y1, uint8_t* y2){
	uint8_t z1[8], z2[8];
	bool eq = true;
	for(int i=0; i<8; i++){
		if(x1[i] != x2[i])
			eq = false;
	}
	if(eq)
		return false;
	memcpy(z1, x1, sizeof(uint8_t) * 8);
	memcpy(z2, x2, sizeof(uint8_t) * 8);
	encrypt(x1, y1);
	encrypt(x2, y2);
	memcpy(z1, y1, sizeof(uint8_t) * 8);
	memcpy(z2, y2, sizeof(uint8_t) * 8);
	inv_mix_nibbles(z1);
	inv_mix_nibbles(z2);
	bool res = true;
	for(int i=0; i<8; i++){
		if(((z1[i] & 0xF0) ^ (z2[i] & 0xF0)) != 0x0)
			res = false;
	}
	return res;
}

// Define C (multiplicative constant) and Inv_p (1/p where p is the probability 
// for the differential to hold) based on the number of rounds of KLEIN
// for 4 and 5 rounds we can use C = 16, the complexity will be low
// otherwise C = 12 works almost every time
#if NR == 4
	#define C 16 
	#define Inv_p 8192
#elif NR == 5
	#define C 16 
	#define Inv_p 524288
#else // NR == 6
    #define C 12
    #define Inv_p 33554432
#endif
#define N_MAX_GOOD 32 // Maximum number of good pairs we want to store

// Arrays to store the good pairs
uint8_t Good_x1[N_MAX_GOOD][8];
uint8_t Good_x2[N_MAX_GOOD][8];
uint8_t Good_y1[N_MAX_GOOD][8];
uint8_t Good_y2[N_MAX_GOOD][8];

int N_good = 0;
// Find good pairs with respect to the differential of Figure d (1 or 2) 
void find_good_pairs(int d){
 	N_good = 0;
	int n_pairs = 0;
	uint8_t x1[8], x2[8], y1[8], y2[8];
    printf("\n");
    progress(d, 0, C);
    // work with C * Inv_p pairs as described in the document
    // (if you want to use this, comment out the calls to progress
    // or it might cause an error!)
	//for(int i=0; (i<C*Inv_p) && (N_good < N_MAX_GOOD); i++){
    
    // alternatively, keep generating pairs until C good pairs are found
	while(N_good < C){
		gen_pair_with_difference(x1, x2, d);
		if(is_good_pair(x1, x2, y1, y2)){
			memcpy(Good_x1[N_good], x1, sizeof(uint8_t) * 8);
			memcpy(Good_x2[N_good], x2, sizeof(uint8_t) * 8);
			N_good++;
            progress(d, N_good, C);
		}
		n_pairs++;
	}
	printf("\nFound %d good pairs among %d pairs (around 2^%d).\n", N_good, n_pairs, (int) ceil(log(n_pairs)/log(2)));
}

// Validate a master key guess on some texts
// key: the current guess for the lower nibbles
// kh: the current guess for the higher nibbles
// (we need it to be uint64_t to handle the case 0xFFFFFFFF without looping forever)
void validate_key(uint8_t* key, uint64_t kh){

	uint8_t k[8];
	memcpy(k, key, sizeof(uint8_t) * 8);
	k[0] ^= (uint8_t) ((kh & 0xF)               << 4);
	k[1] ^= (uint8_t) (((kh & 0xF0) >> 4)       << 4);
	k[2] ^= (uint8_t) (((kh & 0xF00) >> 8)      << 4);
	k[3] ^= (uint8_t) (((kh & 0xF000) >> 12)    << 4);
	k[4] ^= (uint8_t) (((kh & 0xF0000) >> 16)   << 4);
	k[5] ^= (uint8_t) (((kh & 0xF00000) >> 20)  << 4);
	k[6] ^= (uint8_t) (((kh & 0xF000000) >> 24) << 4);
	k[7] ^= (uint8_t) (((kh & 0xF0000000) >> 28)<< 4);

	uint8_t y1[8], y2[8];
	encrypt(Good_x1[0], y1);
	encrypt_with_given_key(Good_x1[0], y2, k);
	bool res = true;
	for(int i=0; i<8; i++){
		if(y1[i] != y2[i])
			res = false;
	}
	if(res){
		// Validate on some more pairs just to make sure
		bool res2 = true;
		for(int j=0; j<16; j++){
            uint8_t x1[8];
			gen_plaintext(x1);
			encrypt(x1, y1);
			encrypt_with_given_key(x1, y2, k);
			for(int i=0; i<8; i++){
				if(y1[i] != y2[i])
					res2 = false;
			}
		}
		if(res2){
            printf("\n");
			printf("Success!\nKey: \n");
			print_matrix(k);
			exit(0);
		}
	}
}

// Bruteforce the higher nibbles of the master key
// (will split work between all cores if the program is compiled with OpenMP)
void recover_higher_nibbles(uint8_t* key){
    #pragma omp parallel for
	for(uint64_t k=0; k <= 0xFFFFFFFF; k++){
		validate_key(key, k);
	}
    #pragma omp barrier
}

// Recover the lower nibbles of the master key
// if d = 1 uses the differential of Figure 1 to recover the lower nibbles of
// bytes 0, 1, 6, 7
// if d = 2 uses the differential of Figure 2 to recover the lower nibbles of
// bytes 2, 3, 4, 5
void recover_lower_nibbles(int d, uint8_t* key){
	find_good_pairs(d);

    // targets: indices of bytes we are working on
    int t1, t2, t3, t4;
    if(d == 1){
        t1 = 0; t2 = 1; t3 = 6; t4 = 7;
    } else {
        t1 = 2; t2 = 3; t3 = 4; t4 = 5;
    }
	
	uint8_t x1[8], x2[8], z1[8], z2[8];
	int skc[16][16][16][16] = {0}; // counters for nibble candidates
    // after processing each good pair, we disable nibble candidates
    // that do not have the highest counter
	bool enabled[16][16][16][16];
	for(uint16_t k1=0; k1<16; k1++){
	for(uint16_t k2=0; k2<16; k2++){
	for(uint16_t k3=0; k3<16; k3++){
	for(uint16_t k4=0; k4<16; k4++){
		enabled[k1][k2][k3][k4] = true;
	}}}}

	int e = 65536; // stores the number of enabled candidates
	for(int i=0; i<N_good; i++){
		memcpy(x1, Good_x1[i], sizeof(uint8_t) * 8);
		memcpy(x2, Good_x2[i], sizeof(uint8_t) * 8);
		memcpy(z1, x1, sizeof(uint8_t) * 8);
		memcpy(z2, x2, sizeof(uint8_t) * 8);
		for(uint16_t k1=0; k1<16; k1++){
		for(uint16_t k2=0; k2<16; k2++){
		for(uint16_t k3=0; k3<16; k3++){
		for(uint16_t k4=0; k4<16; k4++){

            // apply the guess at target indices
			z1[t1] ^= (uint8_t) k1;
			z1[t2] ^= (uint8_t) k2;
			z1[t3] ^= (uint8_t) k3;
			z1[t4] ^= (uint8_t) k4;

			z2[t1] ^= (uint8_t) k1;
			z2[t2] ^= (uint8_t) k2;
			z2[t3] ^= (uint8_t) k3;
			z2[t4] ^= (uint8_t) k4;

			sub_nibbles(z1);
			sub_nibbles(z2);

			bool ok = false; 
			uint8_t a = ((z1[t1] ^ z2[t1]) & 0x8);
			uint8_t b = ((z1[t2] ^ z2[t2]) & 0x8);
			uint8_t c = ((z1[t3] ^ z2[t3]) & 0x8);
			uint8_t d = ((z1[t4] ^ z2[t4]) & 0x8); 
            // validate the guess
            // guess is good iff a, b, c, d have same most significant bit
            // (Proposition 1 of "Cryptanalysis of KLEIN (Full version)")
			if( (a == b) && (b == c) && (c == d) )
				ok = true;

			if(ok && enabled[k1][k2][k3][k4])
				skc[k1][k2][k3][k4]++;

			memcpy(z1, x1, sizeof(uint8_t) * 8);
			memcpy(z2, x2, sizeof(uint8_t) * 8);
		}}}}
        // disable candidates that do not have the highest counter
		int best = 0;
		for(uint16_t k1=0; k1<16; k1++){
		for(uint16_t k2=0; k2<16; k2++){		
		for(uint16_t k3=0; k3<16; k3++){
		for(uint16_t k4=0; k4<16; k4++){
			if(skc[k1][k2][k3][k4] > best)
				best = skc[k1][k2][k3][k4];
		}}}}
		for(uint16_t k1=0; k1<16; k1++){
		for(uint16_t k2=0; k2<16; k2++){		
		for(uint16_t k3=0; k3<16; k3++){
		for(uint16_t k4=0; k4<16; k4++){
			if((enabled[k1][k2][k3][k4]) && (skc[k1][k2][k3][k4] < best)){
				enabled[k1][k2][k3][k4] = false;
				e--;
			}
		}}}}
	}

	printf("%d possible combination(s) for lower nibbles at indices %d, %d, %d, %d.\n", e, t1, t2, t3, t4);
	for(uint16_t k1=0; k1<16; k1++){
	for(uint16_t k2=0; k2<16; k2++){		
	for(uint16_t k3=0; k3<16; k3++){
	for(uint16_t k4=0; k4<16; k4++){
		if(enabled[k1][k2][k3][k4]){
			key[t1] ^= (uint8_t) k1; key[t2] ^= (uint8_t) k2;
            key[t3] ^= (uint8_t) k3; key[t4] ^= (uint8_t) k4;
            if(d == 1) {
			    recover_lower_nibbles(2, key);
            } else {
                printf("\nCurrent combination for the lower nibbles:\n");
                print_lower(key);
                recover_higher_nibbles(key);
            }
			key[t1] ^= (uint8_t) k1; key[t2] ^= (uint8_t) k2;
            key[t3] ^= (uint8_t) k3; key[t4] ^= (uint8_t) k4;
		}
	}}}}
}

void key_recovery(){
    uint8_t key[8] = {0};
    recover_lower_nibbles(1, key);
}

void main(){
    srand(time(NULL));
    init_cipher();
	key_recovery();
}
