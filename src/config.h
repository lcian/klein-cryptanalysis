#include <stdbool.h>
#include <stdint.h>

// Number of rounds
#define NR 5

// Master key
static const uint8_t Key[8] = {
    0x1A, 0x09, 0x43, 0x6D,
    0x5F, 0x93, 0x16, 0x68
};

static const bool random_key = false;
static const bool print_key = false;
