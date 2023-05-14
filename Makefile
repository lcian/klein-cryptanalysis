attack: attack.c klein.c klein.h common.c common.h speedklein64.h kleinSbox.h config.h
	clang attack.c common.c klein.c speedklein64.h kleinSbox.h config.h -march=native -O3 -fopenmp -lm -Wno-incompatible-pointer-types -Wno-main-return-type
