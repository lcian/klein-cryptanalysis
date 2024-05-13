#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Print the 64 bit value s in matrix format
void print_matrix(uint8_t *s) {
    for (int i = 0; i < 8; i++) {
        printf("%02X ", (uint8_t)s[i]);
        if (i == 3) {
            printf("\n");
        }
    }
    printf("\n");
}

// Print only the lower 4-bit nibbles of the 64 bit value s in matrix format
void print_lower(uint8_t *s) {
    for (int i = 0; i < 8; i++) {
        printf(" %X ", (uint8_t)(s[i] & 0x0F));
        if (i == 3) {
            printf("\n");
        }
    }
    printf("\n");
}

// Progress bar
char spaces[80];
char equals[80];
void progress(int d, int i, int n) {
    int barlen = (i * 20) / n;
    int spclen = 20 - barlen;
    memset(equals, '=', barlen);
    equals[barlen] = '\0';
    memset(spaces, ' ', spclen);
    spaces[spclen] = '\0';
    printf("\rFinding good pairs for %d-th differential [%s%s] %3d", d, equals,
           spaces, i);
    fflush(stdout);
}
