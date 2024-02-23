CC ?= clang

CFLAGS ?= -march=native -O3 -Wno-incompatible-pointer-types -Wno-main-return-type -funroll-loops
LFLAGS ?= -lm
OPENMP ?= -fopenmp

attack: attack.c klein.c klein.h common.c common.h speedklein64.h kleinSbox.h config.h
	$(CC) attack.c common.c klein.c -o attack $(CFLAGS) $(LFLAGS) $(OPENMP)

clean:
	rm -f attack
